const express = require(require('path').resolve('./') + "/node_modules/express");
const router = express.Router();

router.get('/',
    (req, res, next) => {
        res.locals = res.locals || {};
        res.locals.fields = [
            'id',
            'Name',
            'Index',
            'IsVirtual',
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
    router.FindAllDocuments('organization')
);

// router.get('/search',
//     async (req, res, next) => {
//         res.locals = res.locals || {};

//         res.locals.filter = {};
//         if (req.query.id) {
//             res.locals.filter.id = req.query.id;
//         }
//         else if (req.query.search) {
//             let keyword = RegExp.quote(req.query.search, 'i');
//             res.locals.filter.$or = [
//                 { Name: keyword },
//             ];
//         } else {
//             await res.endWithErr(400);
//             return;
//         }

//         res.locals.fields = [
//             'id',
//             'Name',
//             'Index',
//             'IsVirtual',
//             'LastUpdateDate'
//         ];

//         return next();
//     },
//     router.FindDocuments('organization')
// );

// TODO: org name should be unqiue in the same parent
router.post('/', router.CreateDocument('organization'));

// TODO: org name should be unqiue in the same parent
router.put('/', router.UpdateDocument('organization'));

// TODO: should delete recursively
router.delete('/', router.DeleteDocument('organization'));

module.exports = router;
