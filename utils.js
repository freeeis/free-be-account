const crypto = require('./crypto');

const specialNames = [
    'Scope'
];

const EncryptOptions = {
    saltLength: 16,
    sha1Iteration: 1024
}

/**
 *
 * Translate permission object into path list
 * 
 * @param {*} perm 
 * @param {*} k 
 */
function getPermissionPathList(perm, n = '') {
    const ret = [];

    if (perm && typeof perm === 'object') {
        if (n) ret.push(n);

        Object.keys(perm).forEach(k => {
            getPermissionPathList(perm[k], k).forEach(p => {
                ret.push(`${n}/${p}`);
            })
        })
    }

    return ret;
}

function clearPermission(perm) {
    // remove unused fields from permisson object
    // invalid: all values are not object, and all names are in the specified list
    function clearP(p) {

        if (typeof p !== 'object') {
            return false;
        }

        Object.keys(p).forEach(s => {
            if (specialNames.indexOf(s) >= 0) return;

            if (!clearP(p[s])) {
                delete p[s];
            }
        });

        // TODO: add a field if nothing here, otherwise the db will not save it??? should be fixed!!
        if (Object.keys(p).length <= 0) {
            p.has = true;
        }

        return true;
    }

    return clearP(perm);
}

function verifyPassword(pwd, storedPwd = '', method = 'md5') {
    let verified = false;
    let methods = [];

    if (typeof method === 'string') {
        methods.push(method);
    } else if (Array.isArray(method)) {
        methods = method;
    }

    for (let i = 0; i < methods.length; i += 1) {
        const m = methods[i];
        switch (m) {
            case 'md5':
                verified = verified || (crypto.MD5(pwd) === storedPwd);
                break;
            case 'sha1':
                verified = verified || (crypto.sha1(pwd, storedPwd.substring(0, EncryptOptions.saltLength), EncryptOptions.sha1Iteration).toString() === storedPwd.substr(EncryptOptions.saltLength));
                break;
            case 'bcrypt':
                verified = verified || crypto.bcryptVerify(pwd, storedPwd);
                break;
            default:
                verified = verified || (pwd === storedPwd);
        }

        if (verified) return verified;
    }

    return verified;
}

function getClearPwd(pwd, key){
    if(!pwd) return undefined;

    return crypto.encoder.desDecode(pwd.substr(EncryptOptions.saltLength), key);
}

function encryptPwd(pwd, method) {
    let theMethod = [];

    if (typeof method === 'string') {
        theMethod = method;
    } else if (Array.isArray(method)) {
        theMethod = method[0];
    }

    let salt;
    if (theMethod === 'sha1') {
        salt = crypto.generateSalt(EncryptOptions.saltLength / 2);
    }

    switch (theMethod) {
        case 'md5':
            return crypto.MD5(pwd);
        case 'sha1':
            return `${salt}${crypto.sha1(pwd, salt.toString(), EncryptOptions.sha1Iteration)}`;
        case 'bcrypt':
            return crypto.bcrypt(pwd);
        default:
            throw 'Unknown password encrypt method!'
    }
}

async function saveServiceList (app, clean=false) {
    // add app.serviceList into db if not yet
    const checkService = async (perm, parent, pt) => {
        if (!perm || typeof perm !== 'object') return;

        for (let i = 0; i < Object.keys(perm).length; i += 1) {
            const p = Object.keys(perm)[i];

            // in case the developer didn't provide title and description information
            perm[p] = perm[p] || {
                title: p,
                description: p,
            };

            // TODO: notify user if they are creating permission with these names
            if (['title', 'description', 'scope', 'label'].indexOf(p.toLowerCase()) >= 0) continue;

            let newCreated;
            const existCount = await app.models['permission'].countDocuments({ Name: p, Path: `${pt}/${p}` });
            if (existCount <= 0) {
                const newDoc = {
                    Name: p,
                    Title: perm[p].title,
                    Description: typeof perm[p].description === 'string' ? perm[p].description : JSON.stringify(perm[p].description),
                    Index: i + 1,
                    Path: `${pt}/${p}`
                };
                if (parent) newDoc.Parent = parent;

                try{
                    newCreated = await app.models.permission.create(newDoc);
                } catch(ex) {
                    app.logger.error(ex.message);
                }
            } else {
                newCreated = (await app.models['permission'].findOne({ Name: p, Path: `${pt}/${p}`}));
                
                // update
                newCreated.Title = perm[p].title;
                newCreated.Description = typeof perm[p].description === 'string' ? perm[p].description : JSON.stringify(perm[p].description);
                if(parent) newCreated.Parent = parent;
                newCreated.Index = i + 1;
                await newCreated.save();
            }

            if (newCreated) {
                await checkService(perm[p], newCreated.id, `${pt}/${p}`);
            }
        }
    };

    // clear all built-in permissions first
    if(clean){
        const userCreatedList = await app.models.permission.find({ BuiltIn: false });
        if(userCreatedList && userCreatedList.length > 0){
            const uclIds = [];
            const addParentId = async (p) => {
                if(!p) return;

                const parent = await app.models.permission.findOne({id: p});

                if(parent && uclIds.indexOf(parent.id) < 0){
                    uclIds.push(parent.id);
                }

                await addParentId(parent.Parent);
            }
            for (let i = 0; i < userCreatedList.length; i += 1) {
                const ucli = userCreatedList[i];
            
                uclIds.push(ucli.id);

                await addParentId(ucli.Parent);
            }

            // remove all built-in
            await app.models.permission.remove({id: {$nin: uclIds}});
        }
    }

    const serviceList = app.ctx.serviceList();
    await checkService(serviceList, undefined, '');
}

module.exports = {
    clearPermission,
    getPermissionPathList,
    verifyPassword,
    encryptPwd,
    getClearPwd,
    crypto,
    saveServiceList,
}