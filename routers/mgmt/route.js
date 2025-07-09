const path = require('path');
const express = require(path.resolve('./') + "/node_modules/express");
const router = express.Router();
const { AccountAuditStatus } = require('../../enum');
const { clearPermission, encryptPwd, crypto } = require('../../utils');

const accountFilters = [
    {
        Name: 'id',
        Type: 'String',
        Info: {
            Separate: true,
        },
    },
    {
        Name: 'LastUpdateDate',
        Type: 'DateRange',
    },
    {
        Name: 'Enabled',
        Type: 'Select',
        Options: [
            {
                Value: true,
            },
            {
                Value: false,
            },
        ],
    },
    {
        Name: 'Profile.Name',
        Type: 'String',
    },
    {
        Name: 'Profile.Title',
        Type: 'String',
    },
    {
        Name: 'PhoneNumber',
        Type: 'String',
    },
    {
        Name: 'UserName',
        Type: 'String',
    },
];

router.get('/', async (req, res, next) => {
    res.locals.fields = [
        'id',
        'LastUpdateDate',
        'Profile',
        'PhoneNumber',
        'Enabled',
        'Org',
        'Labels',
        'Status'
    ];

    res.locals.filter = Object.assign({ Saved: true }, res.app.modules['core-modules'].generateQueryFilter(accountFilters, req.query), res.locals.filter);

    // add summary
    if (router.mdl.config.accountRequireAudit) {
        res.locals.data.summary = {};
        res.locals.data.summary.auditing = await res.app.models['account'].countDocuments({...res.locals.filter, Saved: true, Status: AccountAuditStatus.Auditing });
        res.locals.data.summary.passed = await res.app.models['account'].countDocuments({...res.locals.filter, Saved: true, Status: AccountAuditStatus.Passed });
        res.locals.data.summary.failed = await res.app.models['account'].countDocuments({...res.locals.filter, Saved: true, Status: AccountAuditStatus.Failed });
    } else {
        // no audit needed, return data for enabled and disabled
        res.locals.data.summary = {};
        res.locals.data.summary.passed = await res.app.models['account'].countDocuments({ Saved: true, Enabled: true });
        res.locals.data.summary.failed = await res.app.models['account'].countDocuments({ Saved: true, Enabled: false });
    }
    
    return next();

}, router.FindDocuments('account', false, async (req, res) => {
    res.locals.data.Filters = accountFilters;

    if (res.locals.data && res.locals.data.total) {
        for (let i = 0; i < res.locals.data.docs.length; i += 1) {
            const doc = res.locals.data.docs[i];
            if (doc && doc.Org) {
                const org = await res.app.models.organization.findOne({ id: doc.Org });
                if (org) {
                    doc.Org = {
                        id: org.id,
                        Name: org.Name
                    }
                }
            }

            doc.Profile = doc.Profile || {};
            doc.Profile.Name = doc.Profile.Name || doc.UserName || '';
        }
    }
}));

router.get('/:id',
    (req, res, next) => {
        if (req.params.id === 'sl') return next('route');

        res.locals.filter = { id: req.params.id };

        res.locals.fields = [
            'id',
            'LastUpdateDate',
            'Profile',
            'PhoneNumber',
            'UserName',
            'Enabled',
            'Org',
            'Status',
            'Permission',
            'Labels'
        ];
        
        return next();
    },
    router.FindDocuments('account', false, (req, res) => {
        if (res.locals.data && res.locals.data.total) {
            res.locals.data = res.locals.data.docs[0];
        } else {
            res.locals.data = {};
        }
    })
);

router.post('/', 
    async (req, res, next) => {
        req.body.Status = AccountAuditStatus.Passed;
        req.body.Saved = true;

        if (req.body.Permission) {
            if (!clearPermission(req.body.Permission)) {
                req.body.Permission = {};
            }

            // permission changed, clear cached account permission
            router.mdl.clearCachedPermission(res.app, req.body.id);
        }

        // make sure the provided permission is in the scope of the current user permission!!
        if(req.user.Permission){
            if(req.user.Permission !== '*') {
                // 根据当前账号的权限，检查所传入的权限中的数据权限配置是否合理，
                // 如果合理，将传入的数据权限保存，并合并到最后的权限中
                const permPathList = router.mdl.utils.getPermissionPathList(req.body.Permission);
                const allPerms = await res.app.models.permission.find({ 
                    Path: { $in: permPathList } , 
                    Enabled: true 
                }).lean();

                const dsScope = {};
                for (let i = 0; i < allPerms.length; i += 1) {
                    const p = allPerms[i].Path;
                    const pDot = p.replace(/^\//, '').replace(/\//g, '.');
                    const uPerm = Object.nestValue(req.user.Permission, pDot);
                    const bPerm = Object.nestValue(req.body.Permission, pDot);

                    if (uPerm && uPerm.Scope && bPerm && bPerm.Scope) {
                        // 当前账号此权限中的数据权限定义
                        for (let j = 0; j < (allPerms[i].Scope || []).length; j += 1) {
                            const sc = allPerms[i].Scope[j];

                            if (!uPerm.Scope[sc.Name] || !bPerm.Scope[sc.Name]) {
                                continue;
                            }

                            const dso = res.app.getContainerContent('DataScope').find(ds => ds.Name === sc.Name);

                            if (dso) {
                                const dsoOptions = dso.Options || [];

                                const dsOpOfCurrentUser = dsoOptions.find(o => o.Value === uPerm.Scope[sc.Name]);
                                const dsOpInBody = dsoOptions.find(o => o.Value === bPerm.Scope[sc.Name]);

                                if (dsOpOfCurrentUser 
                                    && dsOpInBody
                                ) {
                                    if (
                                        (dsOpOfCurrentUser.Level !== void 0) 
                                        && (dsOpInBody.Level !== void 0)
                                        && (dsOpInBody.Level <= dsOpOfCurrentUser.Level)
                                    ) {
                                        Object.setValue(dsScope, `${pDot}.Scope.${sc.Name}`, dsOpInBody.Value);
                                    } else {
                                        Object.setValue(dsScope, `${pDot}.Scope.${sc.Name}`, dsOpOfCurrentUser.Value);
                                    }
                                }
                            }
                        }
                    }
                }

                req.body.Permission = Object.intersection(req.body.Permission, req.user.Permission);
                Object.assign(req.body.Permission, dsScope);
            }
        } else {
            delete req.body.Permission;
        }
        
        // pwd
        if (req.body.Password) {
            const password = crypto.encoder.desDecode(req.body.Password, router.mdl.config.desKey);
            req.body.Password = encryptPwd(password, router.mdl.config.pwdEncryptMethod || 'md5');
        }

        return next();
    },
    router.CreateDocument('account')
);

router.post('/audit',
    async (req, res, next) => {
        if (typeof req.body.Status === 'undefined' ||
            typeof req.body.id === 'undefined' ||
            [
                AccountAuditStatus.Passed,
                AccountAuditStatus.Auditing,
                AccountAuditStatus.Failed
            ].indexOf(req.body.Status) < 0) {
            await res.endWithErr(400);
            return;
        }

        res.locals.body = res.locals.body || {};
        res.locals.body.Status = req.body.Status;

        // set to default permission if change audit status back to auditing
        if (req.body.Status === AccountAuditStatus.Failed) {
            res.locals.body.Permission = {};
        } else if (req.body.Status === AccountAuditStatus.Auditing) {
            res.locals.body.Permission = router.mdl.config.accountDefaultPermissions;
        }

        if (res.locals.body.Permission)
            clearPermission(res.locals.body.Permission);

        res.locals.filter = res.locals.filter || {};
        res.locals.filter.id = req.body.id;

        // set permission 
        // try to use default account permission in the config first
        // if not found use the permission of the org of the account (if have org module loaded)
        if (req.body.Status === res.app.modules.account.AccountAuditStatus.Passed && req.body.id) {
            const account = await res.app.models.account.findOne({ id: req.body.id });
            if (account && account.Org) {
                const accountOrg = await res.app.models.organization.findOne({ id: account.Org });
                if (accountOrg && accountOrg.Permission) {
                    const p = Object.assign({}, accountOrg.Permission);
                    if (res.app.modules.account.utils.clearPermission(p)) {
                        const op = res.locals.CURD.find(op => op.method === 'U' && op.model === 'account');
                        if (op) {
                            op.ctx.body.Permission = p;
                        }
                    }
                }
            }
        }

        return next();
    },
    router.UpdateDocument('account'),
);

router.put('/',
    async (req, res, next) => {
        if (req.body.Permission) {
            if (!clearPermission(req.body.Permission)) {
                req.body.Permission = {};
            }

            // permission changed, clear cached account permission
            router.mdl.clearCachedPermission(res.app, req.body.id);
        }

        // make sure the provided permission is in the scope of the current user permission!!
        if(req.user.Permission){
            if(req.user.Permission !== '*') {
                // 根据当前账号的权限，检查所传入的权限中的数据权限配置是否合理，
                // 如果合理，将传入的数据权限保存，并合并到最后的权限中
                const permPathList = router.mdl.utils.getPermissionPathList(req.body.Permission);
                const allPerms = await res.app.models.permission.find({ 
                    Path: { $in: permPathList } , 
                    Enabled: true 
                }).lean();

                const dsScope = {};
                for (let i = 0; i < allPerms.length; i += 1) {
                    const p = allPerms[i].Path;
                    const pDot = p.replace(/^\//, '').replace(/\//g, '.');
                    const uPerm = Object.nestValue(req.user.Permission, pDot);
                    const bPerm = Object.nestValue(req.body.Permission, pDot);

                    if (uPerm && uPerm.Scope && bPerm && bPerm.Scope) {
                        // 当前账号此权限中的数据权限定义
                        for (let j = 0; j < (allPerms[i].Scope || []).length; j += 1) {
                            const sc = allPerms[i].Scope[j];

                            if (!uPerm.Scope[sc.Name] || !bPerm.Scope[sc.Name]) {
                                continue;
                            }

                            const dso = res.app.getContainerContent('DataScope').find(ds => ds.Name === sc.Name);

                            if (dso) {
                                const dsoOptions = dso.Options || [];

                                const dsOpOfCurrentUser = dsoOptions.find(o => o.Value === uPerm.Scope[sc.Name]);
                                const dsOpInBody = dsoOptions.find(o => o.Value === bPerm.Scope[sc.Name]);

                                if (dsOpOfCurrentUser 
                                    && dsOpInBody
                                ) {
                                    if (
                                        (dsOpOfCurrentUser.Level !== void 0) 
                                        && (dsOpInBody.Level !== void 0)
                                        && (dsOpInBody.Level <= dsOpOfCurrentUser.Level)
                                    ) {
                                        Object.setValue(dsScope, `${pDot}.Scope.${sc.Name}`, dsOpInBody.Value);
                                    } else {
                                        Object.setValue(dsScope, `${pDot}.Scope.${sc.Name}`, dsOpOfCurrentUser.Value);
                                    }
                                }
                            }
                        }
                    }
                }

                req.body.Permission = Object.intersection(req.body.Permission, req.user.Permission);
                Object.assign(req.body.Permission, dsScope);
            }
        } else {
            delete req.body.Permission;
        }

        // pwd
        if (req.body.Password) {
            const password = crypto.encoder.desDecode(req.body.Password, router.mdl.config.desKey);
            req.body.Password = encryptPwd(password, router.mdl.config.pwdEncryptMethod || 'md5');
        }

        return next();
    },
    router.UpdateDocument('account', false, (req, res) => {
        // clear return data
        if (res.locals.data && res.locals.data.id) {
            res.locals.data = { id: res.locals.data.id };
        }
    })
);

router.post('/:id/resetpwd',
    (req, res, next) => {
        if (!req.params.id) {
            res.makeError(401, 'Please specify which account you want to reset!');
            return next('route');
        }

        res.locals.filter = { id: req.params.id };

        res.locals.fields = [
            'Password'
        ];

        res.locals.body = {
            Password: router.mdl.config.defaultPassword
        };

        res.locals.newPwd = router.mdl.config.defaultPassword;

        // set default password
        let clearPwd = router.mdl.config.accountDefaultPasswordRandom ?
            crypto.randomPassword(router.mdl.config.accountDefaultPasswordRandomLength || 6) :
            router.mdl.config.accountDefaultPassword;
            
        clearPwd = clearPwd || res.app.modules.account.config.defaultPassword;
        res.locals.newPwd = clearPwd;

        res.locals.body.Password = res.app.modules.account.utils.encryptPwd(clearPwd, router.mdl.config.pwdEncryptMethod || 'md5');
        
        return next();
    },
    router.UpdateDocument('account', false, (req, res) => {
        // return the new pwd
        if (res.locals.newPwd) {
            res.locals.data = {
                newPwd: res.locals.newPwd
            };
        }
    })
);

router.delete('/', router.DeleteDocument('account'));

router.get(`/search`,
    async (req, res, next) => {
        res.locals = res.locals || {};

        res.locals.filter = {};
        if (req.query.id) {
            res.locals.filter.id = req.query.id;
        }
        else if (req.query.search) {
            let keyword = RegExp.quote(req.query.search, 'i');
            res.locals.filter.$or = [
                { Name: keyword },
            ];
        } else {
            await res.endWithErr(400);
            return;
        }

        res.locals.fields = [
            'id',
            'Name',
            'Index',
            'IsVirtual',
            'LastUpdateDate'
        ];

        return next();
    },
    router.FindDocuments('organization')
);

module.exports = router;
