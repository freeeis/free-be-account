const path = require('path');
const express = require(path.resolve('./') + "/node_modules/express");
const router = express.Router();

const subAccountFilters = [
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
];
// sub account list
router.get('/', (req, res, next) => {
    res.locals.filter = {
        Parent: req.user.id
    }

    res.locals.filter = Object.assign({}, res.app.modules['core-modules'].generateQueryFilter(subAccountFilters, req.query), res.locals.filter);

    res.locals.fields = [
        'id',
        'LastUpdateDate',
        'Profile',
        'Enabled',
    ];

    return next();
}, router.FindDocuments('account', false, async (req, res) => {
    // add summary
    res.locals.data.summary = {};
    res.locals.data.summary.enabled = await res.app.models['account'].countDocuments({ Parent: req.user.id, Enabled: true });
    res.locals.data.summary.disabled = await res.app.models['account'].countDocuments({ Parent: req.user.id, Enabled: false });

    res.locals.data.Filters = subAccountFilters;
}));

// create sub accousnt
router.post('/',
    (req, res, next) => {
        req.body.Parent = req.user.id;
        req.body.Enabled = true;
        // req.body.Permission = req.body.Permission || req.user.Permission;
        // cannot change permission of sub account yet, just assign the same permission with the current account
        req.body.Permission = req.user.Permission;
        res.app.modules.account.utils.clearPermission(req.body.Permission);

        // also same Org (but should check whether we have Org module??)
        if (req.user.Org) req.body.Org = req.user.Org;

        // TODO: should not set status here as we don't have this field yet (which was added in passport)
        req.body.Status = '1';

        // TODO: check permission, should not be bigger than the main account

        // password
        if (req.body.Password) {
            const password = res.app.modules.account.utils.crypto.encoder.desDecode(req.body.Password, res.app.modules.account.config.desKey);
            req.body.Password = res.app.modules.account.utils.encryptPwd(password, res.app.modules.account.config.pwdEncryptMethod || 'md5');
        }
        return next();
    },
    router.CreateDocument('account')
);

// specified sub account list
router.get('/:id', (req, res, next) => {
    res.locals.filter = {
        Parent: req.user.id,
        id: req.params.id
    }

    res.locals.fields = [
        'id',
        'Profile',
        'Enabled',
        'PhoneNumber',
        // 'Permission'
    ];

    return next();
}, router.FindDocuments('account', false, (req, res) => {
    if (res.locals.data && res.locals.data.total) {
        res.locals.data = res.locals.data.docs[0];
    }
}));

// update sub account
router.put('/:id',
    (req, res, next) => {
        res.locals.filter = {
            Parent: req.user.id,
            id: req.params.id
        }

        res.locals.fields = [
            'Profile',
            'PhoneNumber',
            'Password',
            'Enabled'
        ];

        if (req.body.Password) {
            const password = res.app.modules.account.utils.crypto.encoder.desDecode(req.body.Password, res.app.modules.account.config.desKey);
            req.body.Password = res.app.modules.account.utils.encryptPwd(password, res.app.modules.account.config.pwdEncryptMethod || 'md5');
        }

        // TODO: check permission, should not be bigger than the main account

        return next();
    },
    router.UpdateDocument('account')
);

// delete sub account
router.delete('/:id',
    (req, res, next) => {
        res.locals.filter = {
            Parent: req.user.id,
            id: req.params.id
        }
        return next();
    },
    router.DeleteDocument('account')
);

module.exports = router;
