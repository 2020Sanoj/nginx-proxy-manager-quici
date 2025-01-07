const fs = require('fs');
const logger = require('./logger').setup;
const certificateModel = require('./models/certificate');
const userModel = require('./models/user');
const userPermissionModel = require('./models/user_permission');
const authModel = require('./models/auth');
const settingModel = require('./models/setting');
const certbot = require('./lib/certbot');

const proxyModel = require('./models/proxy_host');
const redirectModel = require('./models/redirection_host');
const deadModel = require('./models/dead_host');
const streamModel = require('./models/stream');
const internalNginx = require('./internal/nginx');
const utils = require('./lib/utils');

/**
 * Creates a default admin users if one doesn't already exist in the database
 *
 * @returns {Promise}
 */
const setupDefaultUser = () => {
	return userModel
		.query()
		.select(userModel.raw('COUNT(`id`) as `count`'))
		.where('is_deleted', 0)
		.first()
		.then((row) => {
			if (!row.count) {
				// Create a new user and set password
				let email = process.env.INITIAL_ADMIN_EMAIL || 'admin@example.org';
				let password = process.env.INITIAL_ADMIN_PASSWORD || 'iArhP1j7p1P6TA92FA2FMbbUGYqwcYzxC4AVEe12Wbi94FY9gNN62aKyF1shrvG4NycjjX9KfmDQiwkLZH1ZDR9xMjiG2QmoHXi';

				logger.info('Creating a new user: ' + email + ' with password: ' + password);

				const data = {
					is_deleted: 0,
					email: email,
					name: 'Administrator',
					nickname: 'Admin',
					avatar: '',
					roles: ['admin'],
				};

				return userModel
					.query()
					.insertAndFetch(data)
					.then((user) => {
						return authModel
							.query()
							.insert({
								user_id: user.id,
								type: 'password',
								secret: password,
								meta: {},
							})
							.then(() => {
								return userPermissionModel.query().insert({
									user_id: user.id,
									visibility: 'all',
									proxy_hosts: 'manage',
									redirection_hosts: 'manage',
									dead_hosts: 'manage',
									streams: 'manage',
									access_lists: 'manage',
									certificates: 'manage',
								});
							});
					})
					.then(() => {
						logger.info('Initial admin setup completed');
					});
			}
		});
};

/**
 * Creates default settings if they don't already exist in the database
 *
 * @returns {Promise}
 */
const setupDefaultSettings = () => {
	let defaultp = process.env.INITIAL_DEFAULT_PAGE || 'congratulations';
	return settingModel
		.query()
		.select(settingModel.raw('COUNT(`id`) as `count`'))
		.where({ id: 'default-site' })
		.first()
		.then((row) => {
			if (!row.count) {
				settingModel
					.query()
					.insert({
						id: 'default-site',
						name: 'Default Site',
						description: 'What to show when Nginx is hit with an unknown Host',
						value: defaultp,
						meta: {},
					})
					.then(() => {
						logger.info('Default settings added');
					});
			}
		})
		.then(() => {
			settingModel
				.query()
				.where('id', 'default-site')
				.first()
				.then((row) => {
					internalNginx.generateConfig('default', row);
				});
		});
};

/**
 * Installs all Certbot plugins which are required for an installed certificate
 *
 * @returns {Promise}
 */
const setupCertbotPlugins = () => {
	return certificateModel
		.query()
		.where('is_deleted', 0)
		.andWhere('provider', 'letsencrypt')
		.then((certificates) => {
			if (certificates && certificates.length > 0) {
				const plugins = [];
				const promises = [];

				certificates.map(function (certificate) {
					if (certificate.meta && certificate.meta.dns_challenge === true) {
						if (plugins.indexOf(certificate.meta.dns_provider) === -1) {
							plugins.push(certificate.meta.dns_provider);
						}
						fs.writeFileSync('/tmp/certbot-credentials/credentials-' + certificate.id, certificate.meta.dns_provider_credentials, { mode: 0o600 });
					}
				});

				return certbot.installPlugins(plugins).then(() => {
					if (promises.length > 0) {
						return Promise.all(promises).then(() => {
							logger.info('Added Certbot plugins ' + plugins.join(', '));
						});
					}
				});
			}
		});
};

/**
 * regenerate all hosts if needed
 *
 * @returns {Promise}
 */
const regenerateAllHosts = () => {
	if (process.env.REGENERATE_ALL === 'true') {
		return proxyModel
			.query()
			.where('is_deleted', 0)
			.andWhere('enabled', 1)
			.withGraphFetched('[access_list.[clients, items], certificate]')
			.then((rows) => {
				if (rows && rows.length > 0) {
					internalNginx.bulkGenerateConfigs('proxy_host', rows);
				}
			})
			.then(() => {
				return redirectModel
					.query()
					.where('is_deleted', 0)
					.andWhere('enabled', 1)
					.withGraphFetched('[certificate]')
					.then((rows) => {
						if (rows && rows.length > 0) {
							internalNginx.bulkGenerateConfigs('redirection_host', rows);
						}
					});
			})
			.then(() => {
				return deadModel
					.query()
					.where('is_deleted', 0)
					.andWhere('enabled', 1)
					.withGraphFetched('[certificate]')
					.then((rows) => {
						if (rows && rows.length > 0) {
							internalNginx.bulkGenerateConfigs('dead_host', rows);
						}
					});
			})
			.then(() => {
				return streamModel
					.query()
					.where('is_deleted', 0)
					.andWhere('enabled', 1)
					.then((rows) => {
						if (rows && rows.length > 0) {
							internalNginx.bulkGenerateConfigs('stream', rows);
						}
					});
			})
			.then(() => {
				utils.writeHash();
			});
	}
};

module.exports = function () {
	return setupDefaultUser().then(setupDefaultSettings).then(setupCertbotPlugins).then(regenerateAllHosts);
};
