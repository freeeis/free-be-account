const path = require('path');
const express = require(path.resolve('./') + "/node_modules/express");
const router = express.Router();
const utils = require('../../utils');

router.get('/',
    async (req, res, next) => {
        res.locals.filter = {
            Parent: req.query.Parent || {
                $exists: false,
                $eq: null
            },
        };

        // add app.serviceList into db if not yet
        // TODO: we force clean up all built-in permissions here, any problems?
        // it will remove all the data scope!!!!!!!!!
        await utils.saveServiceList(res.app, false);

        // add form fields
        const Fields = Object.assign([], router.mdl.config.permFields);
        Fields.push(
            {
                Name: 'Scope',
                Label: router.mdl.t('scope-field-label'),
                Type: 'DynamicList',
                Options: {
                    Columns: [
                        {
                            Name: 'Name',
                            Label: router.mdl.t('scope-params-header-label'),
                            Type: 'Select',
                            Options: res.app.getContainerContent('DataScope').map(ds => {
                                const ret = {
                                    Label: ds.Label,
                                    Value: ds.Name,
                                };

                                if (ds && ds.Params && ds.Params.length > 0) {
                                    ret.Extra = {
                                        Label: router.mdl.t('scope-params-label'),
                                        Name: 'Params',
                                        Type: 'FixedList',
                                        Options: {
                                            Columns: ds.Params,
                                            Default: [{}]
                                        }
                                    }
                                }

                                return ret;
                            }),
                        },
                    ],
                },
            }
        );

        res.addData({ Fields }, false)

        return next();
    },
    router.FindAllDocuments('permission')
);

router.post('/',
    async (req, res, next) => {
        if (!req.body.Name || !req.body.Title) {
            res.makeError(201, router.mdl);
            return;
        }

        let parent;
        if (req.body.Parent) {
            parent = await res.app.models.permission.findOne({ id: req.body.Parent });
            if (!parent || !parent.Path) {
                res.makeError(211, router.mdl);
                return;
            }
        }

        req.body.Path = `${parent ? parent.Path : ''}/${req.body.Name}`
        req.body.BuiltIn = false;

        return next();
    },
    router.CreateDocument('permission')
);

router.put('/', router.UpdateDocument('permission'));

router.delete('/', router.DeleteDocument('permission'));

module.exports = router;
