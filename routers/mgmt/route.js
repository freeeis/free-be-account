const path = require('path');
const express = require(path.resolve('./') + "/node_modules/express");
const router = express.Router();
const { AccountAuditStatus } = require('../../enum');
const { clearPermission, encryptPwd, crypto } = require('../../utils');

// TODO: i18n translate
const accountFilters = [
    {
        Name: 'LastUpdateDate',
        Type: 'DateRange',
        Label: '更新日期',
        Placeholder: '请选择',
    },
    {
        Name: 'Enabled',
        Type: 'Select',
        Label: '激活状态',
        Placeholder: '请选择',
        Options: [
            {
                Label: '已激活',
                Value: true,
            },
            {
                Label: '未激活',
                Value: false,
            },
        ],
    },
    {
        Name: 'Profile.Name',
        Type: 'String',
        Label: '姓名',
    },
    {
        Name: 'Profile.Title',
        Type: 'String',
        Label: '职务',
    },
    {
        Name: 'PhoneNumber',
        Type: 'String',
        Label: '手机号',
    },
    {
        Name: 'UserName',
        Type: 'String',
        Label: '用户名',
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
    ];

    res.locals.filter = Object.assign({ Saved: true }, res.app.modules['core-modules'].generateQueryFilter(accountFilters, req.query), res.locals.filter);

    res.locals.data.summary = {};
    res.locals.data.summary.auditing = await res.app.models['account'].countDocuments({...res.locals.filter, Status: AccountAuditStatus.Auditing });
    res.locals.data.summary.passed = await res.app.models['account'].countDocuments({...res.locals.filter, Status: AccountAuditStatus.Passed });
    res.locals.data.summary.failed = await res.app.models['account'].countDocuments({...res.locals.filter, Status: AccountAuditStatus.Failed });

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
    (req, res, next) => {
        req.body.Status = AccountAuditStatus.Passed;

        if (req.body.Permission) {
            if (!clearPermission(req.body.Permission)) {
                req.body.Permission = {};
            }
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
            let keyword = RegExp.quote(req.query.search);
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
