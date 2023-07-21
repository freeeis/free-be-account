const express = require(require('path').resolve('./') + "/node_modules/express");
const router = express.Router();

// change phone number
router.put('/',
    async (req, res, next) => {
        if (!req.body.ophone || !req.body.phone) {
            res.makeError(300, 'Phone number is incorrect!', router.mdl);
            return next('route');
        }

        const ophone = res.app.modules.account.utils.crypto.encoder.desDecode(req.body.ophone, res.app.modules.account.config.desKey);

        if (ophone !== req.user.PhoneNumber || ophone.length < 11) {
            res.makeError(300, 'Phone number is incorrect!', router.mdl);
            return next('route');
        }

        // TODO: validate the phone number with correct logic
        if (!req.body.phone || req.body.phone.length < 11) {
            res.makeError(301, 'New phone number is incorrect!', router.mdl);
            return next('route');
        }

        // update phone number
        res.locals.body = {};
        res.locals.body.PhoneNumber = res.app.modules.account.utils.crypto.encoder.desDecode(req.body.phone, res.app.modules.account.config.desKey);

        const oResult = await router.mdl.sms.verify(ophone, req.body.ocode);
        if (!oResult) {
            res.makeError(400, 'Verification code for the old phone is incorrect!', router.mdl);
            await res.app.cache.del(ophone);
            await res.app.cache.del(res.locals.body.PhoneNumber);
            return next('route');
        }

        const result = await router.mdl.sms.verify(res.locals.body.PhoneNumber, req.body.code);
        if (!result) {
            res.makeError(405, 'Verification code for the new phone is incorrect!', router.mdl);
            await res.app.cache.del(ophone);
            await res.app.cache.del(res.locals.body.PhoneNumber);
            return next('route');
        }

        // update password
        if (req.body.Password) {
            const password = res.app.modules.account.utils.crypto.encoder.desDecode(req.body.Password, res.app.modules.account.config.desKey);
            if (password) {
                res.locals.body.Password = res.app.modules.account.utils.encryptPwd(password, res.app.modules.account.config.pwdEncryptMethod || 'md5');
            }
        }

        const existPhone = await res.app.models.account.countDocuments({ PhoneNumber: res.locals.body.PhoneNumber });
        if (existPhone) {
            res.makeError(402, 'Phone number is already in use!', router.mdl);
            return next('route');
        }

        res.locals.body.Profile = req.user.Profile || {};
        res.locals.body.Profile.Mobile = res.locals.body.PhoneNumber;
        // if user name is the old phone number, set it to the new phone number
        if (res.locals.body.UserName === ophone) {
            res.locals.body.UserName = res.locals.body.PhoneNumber;
        }

        res.locals.filter = { id: req.user.id };
        res.locals.fields = [
            'PhoneNumber',
            'Password',
            'UserName',
            'Profile',
        ];

        return next();
    },
    router.UpdateDocument('account'),
);

module.exports = router;
