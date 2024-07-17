const express = require("express");
const app = express();
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
require("dotenv").config();

const port = process.env.PORT || 5000;

// middleware
app.use(
  cors({
    origin: process.env.CLIENT,
  })
);
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster1.iq3jpr7.mongodb.net/?retryWrites=true&w=majority&appName=Cluster1`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();
    // Collections (Direct interaction without schemas)
    const db = client.db("Secure-Pay");
    await db.collection("users").createIndex({ email: 1 }, { unique: true });
    await db
      .collection("users")
      .createIndex({ mobileNumber: 1 }, { unique: true });

    // Authentication middleware
    const authMiddleware = (req, res, next) => {
      const token = req.header("Authorization");
      if (!token)
        return res.status(401).send("Access denied. No token provided.");

      try {
        const decoded = jwt.verify(token.split(" ")[1], "your_jwt_secret");
        req.user = decoded;

        next();
      } catch (error) {
        res.status(400).send("Invalid token");
      }
    };

    app.get("/api/user/info", authMiddleware, async (req, res) => {
      try {
        const user = await db
          .collection("users")
          .findOne({ _id: new ObjectId(req.user.id) });
        if (!user) return res.status(404).send("User not found");
        res.status(200).send({
          name: user.name,
          email: user.email,
          mobileNumber: user.mobileNumber,
          role: user.role,
          balance: user.balance,
          status: user.status,
        });
      } catch (error) {
        res.status(400).send(error.message);
        console.log(error.message);
      }
    });

    // Routes
    app.post("/api/auth/register", async (req, res) => {
      const { name, pin, mobileNumber, email, role } = req.body;

      // Check if user already exists with the given email or mobile number
      const existingUser = await db.collection("users").findOne({
        $or: [{ email }, { mobileNumber }],
      });

      if (existingUser) {
        return res.status(400).send("User already exists");
      }

      // Hash the PIN
      const hashedPin = await bcrypt.hash(pin, 10);

      const newUser = {
        name,
        pin: hashedPin,
        mobileNumber,
        email,
        role,
        status: "pending",
        balance: 0,
      };

      try {
        await db.collection("users").insertOne(newUser);
        res
          .status(201)
          .send("Registered successfully, waiting for admin approval");
      } catch (error) {
        res.status(400).send(error.message);
      }
    });

    app.post("/api/auth/login", async (req, res) => {
      const { identifier, pin } = req.body;
      const user = await db.collection("users").findOne({
        $or: [{ mobileNumber: identifier }, { email: identifier }],
      });

      if (!user) return res.status(400).send("User not found");

      const isMatch = await bcrypt.compare(pin, user.pin);
      if (!isMatch) return res.status(400).send("Invalid PIN");

      const token = jwt.sign(
        { id: user._id, role: user.role }, // Include role in the payload
        "your_jwt_secret",
        { expiresIn: "1h" }
      );

      res.status(200).send({
        message: "Login Successful",
        token: token,
      });
    });

    const adminMiddleware = (req, res, next) => {
      if (req.user.role !== "admin") {
        return res.status(403).send("Access denied. Admins only.");
      }
      next();
    };

    // Get all users
    app.get(
      "/api/admin/users",
      [authMiddleware, adminMiddleware],
      async (req, res) => {
        try {
          const users = await db
            .collection("users")
            .find({ role: { $ne: "admin" } })
            .toArray();
          res.status(200).send(users);
        } catch (error) {
          res.status(400).send(error.message);
        }
      }
    );

    // Search users by name
    app.get(
      "/api/admin/users/search",
      [authMiddleware, adminMiddleware],
      async (req, res) => {
        const { name } = req.query;
        try {
          const users = await db
            .collection("users")
            .find({
              name: { $regex: new RegExp(name, "i") },
              role: { $ne: "admin" },
            })
            .toArray();
          res.status(200).send(users);
        } catch (error) {
          res.status(400).send(error.message);
        }
      }
    );

    // Activate/Block user account
    app.post(
      "/api/admin/users/:id/status",
      [authMiddleware, adminMiddleware],
      async (req, res) => {
        const { id } = req.params;
        const { status } = req.body; // status can be 'active' or 'blocked'

        try {
          const user = await db
            .collection("users")
            .findOne({ _id: new ObjectId(id) });

          if (!user) {
            return res.status(404).send("User not found");
          }

          // Check if the user is being activated for the first time from a pending state
          if (status === "active" && user.status === "pending") {
            let bonus = 0;
            if (user.role === "agent") {
              bonus = 10000; // Bonus for agents
            } else {
              bonus = 40; // Bonus for normal users
            }

            await db.collection("users").updateOne(
              { _id: new ObjectId(id) },
              {
                $set: { status },
                $inc: { balance: bonus },
              }
            );
          } else {
            // Just update the status without changing the balance
            await db
              .collection("users")
              .updateOne({ _id: new ObjectId(id) }, { $set: { status } });
          }

          res.status(200).send("User status updated successfully");
        } catch (error) {
          res.status(400).send(error.message);
        }
      }
    );

    app.post("/api/user/send-money", authMiddleware, async (req, res) => {
      const { recipientMobile, amount } = req.body;
      const sender = await db
        .collection("users")
        .findOne({ _id: new ObjectID(req.user.id) });

      if (sender.balance < amount)
        return res.status(400).send("Insufficient balance");

      const recipient = await db
        .collection("users")
        .findOne({ mobileNumber: recipientMobile });
      if (!recipient) return res.status(404).send("Recipient not found");

      try {
        await db
          .collection("users")
          .updateOne(
            { _id: new ObjectID(req.user.id) },
            { $inc: { balance: -amount } }
          );
        await db
          .collection("users")
          .updateOne(
            { _id: new ObjectID(recipient._id) },
            { $inc: { balance: amount } }
          );
        res.status(200).send("Money sent successfully");
      } catch (error) {
        res.status(400).send(error.message);
      }
    });

    app.post("/api/user/cash-out", authMiddleware, async (req, res) => {
      const { amount } = req.body;
      const user = await db
        .collection("users")
        .findOne({ _id: new ObjectID(req.user.id) });

      if (user.balance < amount)
        return res.status(400).send("Insufficient balance");

      try {
        await db
          .collection("users")
          .updateOne(
            { _id: new ObjectID(req.user.id) },
            { $inc: { balance: -amount } }
          );
        res.status(200).send("Cash out successful");
      } catch (error) {
        res.status(400).send(error.message);
      }
    });

    app.get("/api/user/balance", authMiddleware, async (req, res) => {
      const user = await db
        .collection("users")
        .findOne({ _id: new ObjectID(req.user.id) });
      res.status(200).send({ balance: user.balance });
    });
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("hello");
});

app.listen(port, () => {
  console.log(`server running ${port}`);
});
