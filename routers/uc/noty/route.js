const express = require(require('path').resolve('./') + "/node_modules/express");
const router = express.Router();

router.get('/count',
    async (req, res, next) => {
        const count = await res.app.models.system_notification.countDocuments({
            User: req.user.id,
            Read: false,
        });

        res.addData({
            count,
        }, true);

        return next();
    },
);

router.get('/', 
    (req, res, next) => {
        res.locals.filter = {
            User: req.user.id,
        };

        res.locals.fields = [
            'id',
            'CreatedDate',

            'Title',
            'Content',
            'Read',
            'Category',
        ];

        return next();
    },
    router.FindDocuments('system_notification'),
);

router.put('/read/:id',
    (req, res, next) => {
        res.locals.filter = {
            id: req.params.id,
            User: req.user.id,
            Read: false,
        };

        res.locals.fields = [
            'Read',
        ]

        res.locals.body = {
            Read: true,
        };

        return next();
    },
    router.UpdateDocument('system_notification'),
);

module.exports = router;
