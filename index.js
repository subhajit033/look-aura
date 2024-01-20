const express = require("express");
const app = express();
const port = process.env.PORT || 5000;
const cors = require("cors");
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const ACCESS_TOKEN = process.env.ACCESS_TOKEN
const jwt = require("jsonwebtoken");


app.use(cors());
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_NAME}:${process.env.DB_PASSWORD}@cluster0.wxzkvmx.mongodb.net/?retryWrites=true&w=majority`;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

const verifyJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).send({ message: "Unauthorize Access" });
    }
    const token = authHeader.split(" ")[1];
    jwt.verify(token, ACCESS_TOKEN, function (error, decoded) {
        if (error) {
            return res.status(401).send({ message: "Unauthorize Access" });
        }
        req.decoded = decoded;
        next();
    })
}

const forbiddenAccess = (req, res, next) => {
    if (req.decoded.email === req.query.user) {
        next();
    }
    else {
        return res.status(403).send({ message: "Forbidden Access" });
    }
}


const run = async () => {
    const AllDesigns = client.db("Client1").collection("AllDesigns");
    const Users = client.db("Client1").collection("Users");
    const Packages = client.db("Client1").collection("Package");
    const Payments = client.db("Client1").collection("Payment");
    const Carts = client.db("Client1").collection("Cart");
    const Tags = client.db("Client1").collection("Tag");
    try {

        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded.email;
            const result = await Users.find({ email: email }).project({ role: 1 }).toArray();
            if (result.length > 0) {
                if (result[0].role === 'admin') {
                    next();
                }
                else {
                    return res.status(401).send({ message: "Unauthorize Access" });
                }
            }
            else {
                return res.status(401).send({ message: "Unauthorize Access" });
            }
        }
        const verifyDesigner = async (req, res, next) => {
            const email = req.decoded.email;
            const result = await Users.find({ email: email }).project({ role: 1 }).toArray();
            if (result.length > 0) {
                if (result[0].role === 'designer') {
                    next();
                }
                else {
                    return res.status(401).send({ message: "Unauthorize Access" });
                }
            }
            else {
                return res.status(401).send({ message: "Unauthorize Access" });
            }
        }

        app.get('/', async (req, res) => {
            res.send("Server running");
        });



        app.post("/addUser", verifyJWT, verifyAdmin, async (req, res) => {
            const email = req.body.email;
            const findEmail = await Users.findOne({ email: email });
            if (findEmail) {
                return res.send({ message: "Email already in use" });
            }
            else {
                const result = await Users.insertOne({ ...req.body })
                return res.send(result);
            }
        });

        app.put('/updateUser', verifyJWT, verifyAdmin, async (req, res) => {
            console.log("updateUser", req.body);
            const email = req.body.email;
            const filter = { email: email };
            const updatedDoc = {
                $set: {
                    ...req.body
                }
            };
            const option = { upsert: true };
            const result = await Users.updateOne(filter, updatedDoc, option);
            res.send(result);
        })

        app.delete('/deleteUser', verifyJWT, verifyAdmin, async (req, res) => {
            console.log("delete", req.body);
            const email = req.query.user;
            const result = await Users.deleteOne({ email });
            res.send(result);
        })


        app.post("/addDesign", async (req, res) => {
            console.log(req.body);
            const result = await AllDesigns.insertOne({ ...req.body });
            res.send(result);
        })

        app.post('/login', async (req, res) => {
            const result = await Users.findOne({ $and: [{ email: { $eq: req.body.email } }, { password: { $eq: req.body.password } }] })
            if (result) {
                return res.send({ result: { ...result } });
            }
            else {
                return res.send({ result: false });
            }
        })

        app.put('/changePassword', verifyJWT, forbiddenAccess, async (req, res) => {
            console.log("change password", req.query.user);
            const email = req.query.user;
            const filter = { email: email };
            const updatedDoc = {
                $set: {
                    ...req.body
                }
            };
            const option = { upsert: true };
            const result = await Users.updateOne(filter, updatedDoc, option);
            res.send(result);
        })

        app.post('/jwt', async (req, res) => {
            const email = req.body.email;
            const token = jwt.sign({ email }, ACCESS_TOKEN, { expiresIn: "1h" });
            res.send({ token: token });
        });

        app.get("/allDesigner", verifyJWT, verifyAdmin, async (req, res) => {
            const result = await Users.find({ role: "designer" }).toArray();
            res.send(result);
        })

        app.get('/allNormalUser', verifyJWT, verifyAdmin, async (req, res) => {
            const result = await Users.find({ role: "store" }).toArray();
            res.send(result);
        })

        app.post('/authSubscriberCheck', async (req, res) => {
            const authHeader = req.headers.authorization;
            if (!authHeader) {
                return res.send({ user: false })
            }
            const token = authHeader.split(' ')[1];
            await jwt.verify(token, ACCESS_TOKEN, async function (error, decoded) {
                if (error) {
                    return res.send({ user: false });
                }
                const email = decoded.email;
                const result = await Users.findOne({ email: email });
                if (result) {
                    return res.send({ user: result });
                }
                else {
                    return res.send({ user: false });
                }
            })
        });

        app.get('/adminCheck', async (req, res) => {
            const email = req.query.user;
            const result = await Users.findOne({ email: email });
            res.send({ admin: result.role === "admin" });
        });

        app.get('/designerCheck', async (req, res) => {
            const email = req.query.user;
            const result = await Users.findOne({ email: email });
            res.send({ designer: result.role === "designer" })
        })

        app.get('/reviewDesigns', verifyJWT, verifyAdmin, async (req, res) => {
            let allDesigners = await Users.find({ $and: [{ role: "designer" }, { role: { $ne: "admin" } }] }).toArray();
            let getDesigns = await AllDesigns.find({ isApproved: false }).toArray();
            allDesigners.forEach((designerElement) => {
                let specificDesigns = getDesigns.filter((data) => data.uploaderEmail === designerElement.email);
                designerElement.total_unapproved = specificDesigns.length
            })
            allDesigners = allDesigners.filter((data) => data.total_unapproved !== 0);
            // console.log(allDesigners);
            res.send(allDesigners);
        })

        app.post('/selectedDesigner', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.body.id;
            const result = await Users.find({ _id: new ObjectId(id) }).project({ password: 0 }).toArray();
            res.send({ ...result[0] })
        })

        app.post('/specificUnApprovedItems', verifyJWT, verifyAdmin, async (req, res) => {
            const email = req.body.email;
            const findEmail = await Users.findOne({ email: email });
            if (!findEmail) {
                return res.send(findEmail)
            }
            const result = await AllDesigns.find({ $and: [{ uploaderEmail: email }, { isApproved: false }, { isRejected: { $ne: true } }] }).toArray();
            res.send(result);
        })

        app.post('/specificDesignApproval', verifyJWT, async (req, res) => {
            const id = req.body.id;
            const result = await AllDesigns.findOne({ _id: new ObjectId(id) });
            res.send(result);
        })

        app.put('/approveDesign', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.query.id
            const filter = { _id: new ObjectId(id) };
            const updatedDoc = {
                $set: {
                    ...req.body
                }
            };
            const option = { upsert: true };
            const result = await AllDesigns.updateOne(filter, updatedDoc, option);
            res.send(result);
        })

        app.get("/allDesignsForAdmin", verifyJWT, verifyAdmin, async (req, res) => {
            const email = req.decoded.email;
            let search = req.query.search;
            if(search===""){
                let result = await AllDesigns.find({ $and: [{ isApproved: true }, { isSold: false }] }).toArray();
                result.forEach(element => {
                    let findEmail = element.likes.filter(data => data.email === email);
                    if (findEmail.length !== 0) {
                        element.personReaction = true
                    }
                })
                // console.log(result);
                return res.send(result);
            }
            else{
                let result = await AllDesigns.find({ $and: [{ isApproved: true }, { isSold: false }] }).toArray();
                let filteredData=[]
                result.forEach(element => {
                    let findTag= element.tags.filter(data=>data===search);
                    if(findTag.length!==0){
                        let findEmail = element.likes.filter(data => data.email === email);
                        if (findEmail.length !== 0) {
                            element.personReaction = true
                        }
                        filteredData.push(element);
                    }
                    
                    
                })
                result = [...filteredData];
                // console.log(result);
                return res.send(result);
            }
            
        })

        app.get('/myDesigns', verifyJWT, verifyDesigner, async (req, res) => {
            const email = req.decoded.email;
            let result = await AllDesigns.find({ $and: [{ uploaderEmail: email }, { isApproved: true }] }).toArray();
            result.forEach(element => {
                let findEmail = element.likes.filter(data => data.email === email);
                if (findEmail.length !== 0) {
                    element.personReaction = true
                }
            })
            res.send(result)
        })

        app.get('/designerStatistics', verifyJWT, verifyDesigner, async (req, res) => {
            const email = req.decoded.email;
            const tempResult = await AllDesigns.find({ uploaderEmail: email }).toArray();
            let result = {}
            let approvedCount = 0;
            let unApprovedCount = 0;
            let rejectedCount = 0;
            tempResult.forEach((element) => {
                if (element.isApproved) {
                    approvedCount += 1;
                }
                if (!element.isApproved) {
                    unApprovedCount += 1
                }
                if (element.isRejected) {
                    rejectedCount += 1;
                }
            })
            result.total_unapproved = unApprovedCount;
            result.total_rejected = rejectedCount;
            result.total_approved = approvedCount;
            result.total_design = tempResult.length;
            res.send(result);
        });

        app.get("/viewAllDesigns", verifyJWT, async (req, res) => {
            const email = req.decoded.email;
            let search = req.query.search;
            if (search === "") {
                let result = await AllDesigns.find({ $and: [{ isApproved: true }, { isSold: false }] }).toArray();
                result.forEach(element => {
                    let findEmail = element.likes.filter(data => data.email === email);
                    if (findEmail.length !== 0) {
                        element.personReaction = true
                    }
                })
                // console.log(result);
                return res.send(result);
            }
            else {
                let result = await AllDesigns.find({ $and: [{ isApproved: true }, { isSold: false }] }).toArray();
                let filteredData = []
                result.forEach(element => {
                    let findTag = element.tags.filter(data => data === search);
                    if (findTag.length !== 0) {
                        let findEmail = element.likes.filter(data => data.email === email);
                        if (findEmail.length !== 0) {
                            element.personReaction = true
                        }
                        filteredData.push(element);
                    }


                })
                result = [...filteredData];
                return res.send(result);
            }
            // const result = await AllDesigns.find({ $and: [{ isApproved: true }, { isSold: false }] }).toArray();
            // res.send(result);
        })

        app.get('/adminStatistics', verifyJWT, verifyAdmin, async (req, res) => {
            const AllUser = await Users.find({ role: { $ne: "admin" } }).toArray();
            const AllDesignerPost = await AllDesigns.find({}).toArray();
            let totalUsers = AllUser.length;
            let totalDesigner = 0;
            let totalShops = 0;
            let PaidShops = 0;
            let UnpaidShops = 0;
            let totalDesigns = AllDesignerPost.length;
            let totalApproveDesigns = 0;
            let totalUnapproved = 0;
            let totalRejected = 0;
            let totalSold = 0;
            let totalUnsold = 0;
            AllUser.forEach(element => {
                if (element.role === 'designer') {
                    totalDesigner += 1;
                }
                if (element.role === 'store') {
                    totalShops += 1;
                }
                if (element.isPaid) {
                    PaidShops += 1;
                }
                if (!element.isPaid && element.role === "store") {
                    UnpaidShops += 1;
                }

            });
            AllDesignerPost.forEach((element) => {
                if (element.isApproved) {
                    totalApproveDesigns += 1;
                }
                if (!element.isApproved) {
                    totalUnapproved += 1
                }
                if (element.isRejected) {
                    totalRejected += 1;
                }
                if (element.isSold) {
                    totalSold += 1;
                }
                if (!element.isSold) {
                    totalUnsold += 1;
                }
            })
            res.send({ totalUsers, totalDesigner, totalShops, PaidShops, UnpaidShops, totalDesigns, totalApproveDesigns, totalUnapproved, totalUnsold, totalSold, totalRejected })
        })

        app.post('/postPackage', verifyJWT, verifyAdmin, async (req, res) => {
            // console.log(req.body);
            const result = await Packages.insertOne({ ...req.body })
            res.send(result);
        })

        app.put('/productReaction', verifyJWT, async (req, res) => {
            const id = req.query.id
            const filter = { _id: new ObjectId(id) };
            console.log(req.body);
            const updatedDoc = {
                $set: {
                    ...req.body
                }
            }
            const option = { upsert: true };
            const result = await AllDesigns.updateOne(filter, updatedDoc, option);
            res.send(result);
        })

        app.get('/allPackage', verifyJWT, async (req, res) => {
            const result = await Packages.find({}).toArray();
            res.send(result);
        })

        app.get('/allTag', verifyJWT, async (req, res) => {
            const result = await Tags.find({}).toArray();
            res.send(result);
        })

        app.post('/addTag', verifyJWT, verifyAdmin, async (req, res) => {
            const result = await Tags.insertOne({ ...req.body });
            res.send(result);
        })

        app.delete("/delete-tag", verifyJWT, verifyAdmin, async (req, res) => {
            const name = req.query.name;
            const result = await Tags.deleteOne({ name: name });
            res.send(result);
        })
    }
    finally {

    }
}

run()
    .catch(error => {
        console.log(error.message);
    })


app.listen(port, () => {
    console.log(`listening on port: ${port}`);
})


