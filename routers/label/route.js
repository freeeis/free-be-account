const path = require('path');
const express = require(path.resolve('./') + "/node_modules/express");
const router = express.Router();

router.get('/',
    (req, res, next) => {
        res.locals = res.locals || {};
        res.locals.fields = [
            'id',
            'Name',
            'Index',
            'Enabled',
            'Permission'
        ];
        res.locals.filter = {
            Parent: req.query.Parent || {
                $exists: false,
                $eq: null
            }
        }

        return next();
    },
    router.FindAllDocuments('plabel')
);

router.post('/', router.CreateDocument('plabel'));

router.put('/', router.UpdateDocument('plabel'));

router.delete('/', router.DeleteDocument('plabel'));

module.exports = router;
