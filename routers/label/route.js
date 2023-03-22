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
            'Description',
            'Negative',
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

router.post('/', 
    (req, res, next) => {
        if(req.body.Permission) {
            if (!res.app.modules['passport'].utils.clearPermission(req.body.Permission)) {
                req.body.Permission = {};
            }

            // permission changed, clear all cached account permission
            // TODO: should be optimized??
            res.app.modules['passport'].clearCachedPermission(res.app);
        }

        // when create or update plabel, provided permission should NOT exceed the permission of the current user
        if(req.user.Permission){
            if(req.user.Permission !== '*') {
                req.body.Permission = Object.intersection(req.body.Permission, req.user.Permission);
            }
        } else {
            delete req.body.Permission;
        }
        
        return next();
    },
    router.CreateDocument('plabel')
);

router.put('/', 
    (req, res, next) => {
        if(req.body.Permission) {
            if (!res.app.modules['passport'].utils.clearPermission(req.body.Permission)) {
                req.body.Permission = {};
            }

            // permission changed, clear all cached account permission
            // TODO: should be optimized??
            res.app.modules['passport'].clearCachedPermission(res.app);
        }

        // when create or update plabel, provided permission should NOT exceed the permission of the current user
        if(req.user.Permission){
            if(req.user.Permission !== '*') {
                req.body.Permission = Object.intersection(req.body.Permission, req.user.Permission);
            }
        } else {
            delete req.body.Permission;
        }
        
        return next();
    },
    router.UpdateDocument('plabel')
);

router.delete('/', router.DeleteDocument('plabel'));

module.exports = router;
