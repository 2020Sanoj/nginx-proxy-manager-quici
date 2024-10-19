const express = require('express');
const validator = require('../../lib/validator');
const jwtdecode = require('../../lib/express/jwt-decode');
const apiValidator = require('../../lib/validator/api');
const internalRedirectionHost = require('../../internal/redirection-host');
const schema = require('../../schema');

let router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

/**
 * /api/nginx/redirection-hosts
 */
router
	.route('/')
	.options((req, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())

	/**
	 * GET /api/nginx/redirection-hosts
	 *
	 * Retrieve all redirection-hosts
	 */
	.get((req, res, next) => {
		validator(
			{
				additionalProperties: false,
				properties: {
					expand: {
						$ref: 'common#/properties/expand',
					},
					query: {
						$ref: 'common#/properties/query',
					},
				},
			},
			{
				expand: typeof req.query.expand === 'string' ? req.query.expand.split(',') : null,
				query: typeof req.query.query === 'string' ? req.query.query : null,
			},
		)
			.then((data) => {
				return internalRedirectionHost.getAll(res.locals.access, data.expand, data.query);
			})
			.then((rows) => {
				res.status(200).send(rows);
			})
			.catch(next);
	})

	/**
	 * POST /api/nginx/redirection-hosts
	 *
	 * Create a new redirection-host
	 */
	.post((req, res, next) => {
		apiValidator(schema.getValidationSchema('/nginx/redirection-hosts', 'post'), req.body)
			.then((payload) => {
				return internalRedirectionHost.create(res.locals.access, payload);
			})
			.then((result) => {
				res.status(201).send(result);
			})
			.catch(next);
	});

/**
 * Specific redirection-host
 *
 * /api/nginx/redirection-hosts/123
 */
router
	.route('/:host_id')
	.options((req, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())

	/**
	 * GET /api/nginx/redirection-hosts/123
	 *
	 * Retrieve a specific redirection-host
	 */
	.get((req, res, next) => {
		validator(
			{
				required: ['host_id'],
				additionalProperties: false,
				properties: {
					host_id: {
						$ref: 'common#/properties/id',
					},
					expand: {
						$ref: 'common#/properties/expand',
					},
				},
			},
			{
				host_id: req.params.host_id,
				expand: typeof req.query.expand === 'string' ? req.query.expand.split(',') : null,
			},
		)
			.then((data) => {
				return internalRedirectionHost.get(res.locals.access, {
					id: parseInt(data.host_id, 10),
					expand: data.expand,
				});
			})
			.then((row) => {
				res.status(200).send(row);
			})
			.catch(next);
	})

	/**
	 * PUT /api/nginx/redirection-hosts/123
	 *
	 * Update and existing redirection-host
	 */
	.put((req, res, next) => {
		apiValidator(schema.getValidationSchema('/nginx/redirection-hosts/{hostID}', 'put'), req.body)
			.then((payload) => {
				payload.id = parseInt(req.params.host_id, 10);
				return internalRedirectionHost.update(res.locals.access, payload);
			})
			.then((result) => {
				res.status(200).send(result);
			})
			.catch(next);
	})

	/**
	 * DELETE /api/nginx/redirection-hosts/123
	 *
	 * Update and existing redirection-host
	 */
	.delete((req, res, next) => {
		internalRedirectionHost
			.delete(res.locals.access, { id: parseInt(req.params.host_id, 10) })
			.then((result) => {
				res.status(200).send(result);
			})
			.catch(next);
	});

/**
 * Enable redirection-host
 *
 * /api/nginx/redirection-hosts/123/enable
 */
router
	.route('/:host_id/enable')
	.options((req, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())

	/**
	 * POST /api/nginx/redirection-hosts/123/enable
	 */
	.post((req, res, next) => {
		internalRedirectionHost
			.enable(res.locals.access, { id: parseInt(req.params.host_id, 10) })
			.then((result) => {
				res.status(200).send(result);
			})
			.catch(next);
	});

/**
 * Disable redirection-host
 *
 * /api/nginx/redirection-hosts/123/disable
 */
router
	.route('/:host_id/disable')
	.options((req, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())

	/**
	 * POST /api/nginx/redirection-hosts/123/disable
	 */
	.post((req, res, next) => {
		internalRedirectionHost
			.disable(res.locals.access, { id: parseInt(req.params.host_id, 10) })
			.then((result) => {
				res.status(200).send(result);
			})
			.catch(next);
	});

module.exports = router;