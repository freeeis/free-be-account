const express = require(require('path').resolve('./') + "/node_modules/express");
const router = express.Router();

router.get('/', (req, res, next) => {
    const user = req.user;

    const StepsDefinition = Object.clone(router.mdl.config.infoStepsDefinition || []);

    const extraFields = {};
    if (StepsDefinition[0]) {
        StepsDefinition[0].Fields = StepsDefinition[0].Fields || [];

        for (let i = 0; i < StepsDefinition[0].Fields.length; i += 1) {
            const field = StepsDefinition[0].Fields[i];

            if (field && field.Name) {
                Object.setValue(extraFields, field.Name, Object.nestValue(user, field.Name));
            }
        }

    }

    res.addData({
        ...extraFields,

        PhoneNumber: user.PhoneNumber,
        Org: user.Org,
        Profile: user.Profile,
        Status: user.Status,

        StepsDefinition,
    });

    return next();
});

router.put('/', async (req, res, next) => {
    const user = req.user;

    res.locals.filter = { id: user.id };
    // get new data from request (now only profile can be updated in uc)
    if (req.body.Profile) {
        res.locals.body = { Profile: req.body.Profile };
    } else {
        res.locals.body = { Enabled: user.Enabled };
    }

    return next();
}, router.UpdateDocument('account', false, (req, res) => {
    if (res.locals.data) {

        // only return necessary info
        res.addData({});
    }
}));

// change to editing status
router.post('/edit', async (req, res, next) => {
    // set to default permission 
    const p = res.app.modules.account.config.accountDefaultPermissions;
    res.app.modules.account.utils.clearPermission(p);

    // TODO: should not use mongoose directly
    await res.app.models['account'].update({ id: req.user.id }, { $unset: { Status: 0 }, $set: { Permission: p } });

    res.addData({});

    return next();
});

// submit to audit
router.post('/submit', async (req, res, next) => {
    const user = req.user;

    // save changes first
    if (req.body.Profile) {
        user.Profile = Object.assign(user.Profile, req.body.Profile);
    }

    user.Status = res.app.modules.account.AccountAuditStatus.Auditing;

    // set to default permission 
    const p = res.app.modules.account.config.accountDefaultPermissions;
    res.app.modules.account.utils.clearPermission(p);
    user.Permission = p;

    // save
    await user.save();

    res.addData({});

    return next();
});

module.exports = router;
