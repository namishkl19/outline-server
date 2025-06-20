// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const fs = require('fs');
const http = require('http');
const path = require('path');
const process = require('process');
const prometheus = require('prom-client');
const restify = require('restify');
const corsMiddleware = require('restify-cors-middleware2');

const { RealClock } = require('../infrastructure/clock');
const { PortProvider } = require('../infrastructure/get_port');
const json_config = require('../infrastructure/json_config');
const logging = require('../infrastructure/logging');
const { ApiPrometheusClient, startPrometheus } = require('../infrastructure/prometheus_scraper');
const { RolloutTracker } = require('../infrastructure/rollout');
const version = require('./version');

const { PrometheusManagerMetrics } = require('./manager_metrics');
const { bindService, ShadowsocksManagerService } = require('./manager_service');
const { OutlineShadowsocksServer } = require('./outline_shadowsocks_server');
const { ServerAccessKeyRepository } = require('./server_access_key');
const server_config = require('./server_config');
const {
  OutlineSharedMetricsPublisher,
  PrometheusUsageMetrics,
  RestMetricsCollectorClient,
} = require('./shared_metrics');

const APP_BASE_DIR = path.join(__dirname, '..');
const DEFAULT_STATE_DIR = '/root/shadowbox/persisted-state';
const MMDB_LOCATION_COUNTRY = '/var/lib/libmaxminddb/ip-country.mmdb';
const MMDB_LOCATION_ASN = '/var/lib/libmaxminddb/ip-asn.mmdb';

async function exportPrometheusMetrics(registry, port) {
  return new Promise((resolve) => {
    const server = http.createServer((_, res) => {
      res.setHeader('Content-Type', registry.contentType);
      res.write(registry.metrics());
      res.end();
    });
    server.on('listening', () => {
      resolve(server);
    });
    server.listen({ port, host: 'localhost', exclusive: true });
  });
}

function reserveExistingAccessKeyPorts(keyConfig, portProvider) {
  const accessKeys = keyConfig.data().accessKeys || [];
  const dedupedPorts = new Set(accessKeys.map((ak) => ak.port));
  dedupedPorts.forEach((p) => portProvider.addReservedPort(p));
}

function createRolloutTracker(serverConfig) {
  const rollouts = new RolloutTracker(serverConfig.data().serverId);
  if (serverConfig.data().rollouts) {
    for (const rollout of serverConfig.data().rollouts) {
      rollouts.forceRollout(rollout.id, rollout.enabled);
    }
  }
  return rollouts;
}

async function main() {
  const verbose = process.env.LOG_LEVEL === 'debug';
  logging.info('======== Outline Server main() ========');
  logging.info(`Version is ${version.getPackageVersion()}`);

  const portProvider = new PortProvider();
  const accessKeyConfig = json_config.loadFileConfig(getPersistentFilename('shadowbox_config.json'));
  reserveExistingAccessKeyPorts(accessKeyConfig, portProvider);

  prometheus.collectDefaultMetrics({ register: prometheus.register });

  const metricsCollectorUrl = process.env.SB_METRICS_URL || 'https://prod.metrics.getoutline.org';
  if (!process.env.SB_METRICS_URL) {
    logging.warn('process.env.SB_METRICS_URL not set, using default');
  }

  const DEFAULT_PORT = 8081;
  const apiPortNumber = Number(process.env.SB_API_PORT || DEFAULT_PORT);
  if (isNaN(apiPortNumber)) {
    logging.error(`Invalid SB_API_PORT: ${process.env.SB_API_PORT}`);
    process.exit(1);
  }
  portProvider.addReservedPort(apiPortNumber);

  const serverConfig = server_config.readServerConfig(getPersistentFilename('shadowbox_server_config.json'));

  const proxyHostname = serverConfig.data().hostname;
  if (!proxyHostname) {
    logging.error('Need to specify hostname in shadowbox_server_config.json');
    process.exit(1);
  }

  logging.info(`Hostname: ${proxyHostname}`);
  logging.info(`SB_METRICS_URL: ${metricsCollectorUrl}`);

  const prometheusPort = await portProvider.reserveFirstFreePort(9090);
  const prometheusLocation = `127.0.0.1:${prometheusPort}`;

  const nodeMetricsPort = await portProvider.reserveFirstFreePort(prometheusPort + 1);
  exportPrometheusMetrics(prometheus.register, nodeMetricsPort);
  const nodeMetricsLocation = `127.0.0.1:${nodeMetricsPort}`;

  const ssMetricsPort = await portProvider.reserveFirstFreePort(nodeMetricsPort + 1);
  logging.info(`Prometheus is at ${prometheusLocation}`);
  logging.info(`Node metrics is at ${nodeMetricsLocation}`);

  const prometheusConfigJson = {
    global: {
      scrape_interval: '1m',
    },
    scrape_configs: [
      { job_name: 'prometheus', static_configs: [{ targets: [prometheusLocation] }] },
      { job_name: 'outline-server-main', static_configs: [{ targets: [nodeMetricsLocation] }] },
    ],
  };

  const ssMetricsLocation = `127.0.0.1:${ssMetricsPort}`;
  logging.info(`outline-ss-server metrics is at ${ssMetricsLocation}`);
  prometheusConfigJson.scrape_configs.push({
    job_name: 'outline-server-ss',
    static_configs: [{ targets: [ssMetricsLocation] }],
  });

  const shadowsocksServer = new OutlineShadowsocksServer(
    getBinaryFilename('outline-ss-server'),
    getPersistentFilename('outline-ss-server/config.yml'),
    verbose,
    ssMetricsLocation
  );
  if (fs.existsSync(MMDB_LOCATION_COUNTRY)) {
    shadowsocksServer.configureCountryMetrics(MMDB_LOCATION_COUNTRY);
  }
  if (fs.existsSync(MMDB_LOCATION_ASN)) {
    shadowsocksServer.configureAsnMetrics(MMDB_LOCATION_ASN);
  }

  const isReplayProtectionEnabled = createRolloutTracker(serverConfig).isRolloutEnabled(
    'replay-protection',
    100
  );
  logging.info(`Replay protection enabled: ${isReplayProtectionEnabled}`);
  if (isReplayProtectionEnabled) {
    shadowsocksServer.enableReplayProtection();
  }

  const prometheusConfigFilename = getPersistentFilename('prometheus/config.yml');
  const prometheusTsdbFilename = getPersistentFilename('prometheus/data');
  const prometheusEndpoint = `http://${prometheusLocation}`;
  const prometheusBinary = getBinaryFilename('prometheus');
  const prometheusArgs = [
    '--config.file',
    prometheusConfigFilename,
    '--web.enable-admin-api',
    '--storage.tsdb.retention.time',
    '31d',
    '--storage.tsdb.path',
    prometheusTsdbFilename,
    '--web.listen-address',
    prometheusLocation,
    '--log.level',
    verbose ? 'debug' : 'info',
  ];
  await startPrometheus(
    prometheusBinary,
    prometheusConfigFilename,
    prometheusConfigJson,
    prometheusArgs,
    prometheusEndpoint
  );

  const prometheusClient = new ApiPrometheusClient(prometheusEndpoint);
  if (!serverConfig.data().portForNewAccessKeys) {
    serverConfig.data().portForNewAccessKeys = await portProvider.reserveNewPort();
    serverConfig.write();
  }

  const accessKeyRepository = new ServerAccessKeyRepository(
    serverConfig.data().portForNewAccessKeys,
    proxyHostname,
    accessKeyConfig,
    shadowsocksServer,
    prometheusClient,
    serverConfig.data().accessKeyDataLimit
  );

  const metricsReader = new PrometheusUsageMetrics(prometheusClient);
  const managerMetrics = new PrometheusManagerMetrics(prometheusClient);
  const metricsCollector = new RestMetricsCollectorClient(metricsCollectorUrl);
  const metricsPublisher = new OutlineSharedMetricsPublisher(
    new RealClock(),
    serverConfig,
    accessKeyConfig,
    metricsReader,
    metricsCollector
  );

  const managerService = new ShadowsocksManagerService(
    process.env.SB_DEFAULT_SERVER_NAME || 'Outline Server',
    serverConfig,
    accessKeyRepository,
    shadowsocksServer,
    managerMetrics,
    metricsPublisher
  );

  const certificateFilename = process.env.SB_CERTIFICATE_FILE;
  const privateKeyFilename = process.env.SB_PRIVATE_KEY_FILE;
  const apiServer = restify.createServer({
    certificate: fs.readFileSync(certificateFilename),
    key: fs.readFileSync(privateKeyFilename),
  });

  const cors = corsMiddleware({
    origins: ['*'],
    allowHeaders: [],
    exposeHeaders: [],
    credentials: false,
  });
  apiServer.pre(cors.preflight);
  apiServer.pre(restify.pre.sanitizePath());

  const apiPrefix = process.env.SB_API_PREFIX ? `/${process.env.SB_API_PREFIX}` : '';
  apiServer.use(restify.plugins.jsonp());
  apiServer.use(restify.plugins.bodyParser({ mapParams: true }));
  apiServer.use(cors.actual);
  bindService(apiServer, apiPrefix, managerService);

  apiServer.listen(apiPortNumber, () => {
    logging.info(`Manager listening at ${apiServer.url}${apiPrefix}`);
  });

  await accessKeyRepository.start(new RealClock());
}

function getPersistentFilename(file) {
  const stateDir = process.env.SB_STATE_DIR || DEFAULT_STATE_DIR;
  return path.join(stateDir, file);
}

function getBinaryFilename(file) {
  const binDir = path.join(APP_BASE_DIR, 'bin');
  return path.join(binDir, file);
}

process.on('unhandledRejection', (error) => {
  logging.error(`unhandledRejection: ${error.stack}`);
});

main().catch((error) => {
  logging.error(error.stack);
  process.exit(1);
});
