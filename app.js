const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const app = express();
const port = process.env.PORT || 3000;

// SQLite Database Setup
const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database("twitterClone.db");

app.use(bodyParser.json());

// API 1: User Registration
app.post("/register", async (req, res) => {
  const { username, password, name, gender } = req.body;

  // Check if username already exists
  db.get(
    "SELECT * FROM user WHERE username = ?",
    [username],
    async (err, row) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else if (row) {
        res.status(400).send("User already exists");
      } else if (password.length < 6) {
        res.status(400).send("Password is too short");
      } else {
        try {
          // Hash and salt the password
          const hashedPassword = await bcrypt.hash(password, 10);

          // Insert new user into the database with hashed password
          db.run(
            "INSERT INTO user (name, username, password, gender) VALUES (?, ?, ?, ?)",
            [name, username, hashedPassword, gender],
            (err) => {
              if (err) {
                console.error(err);
                res.status(500).send("Internal Server Error");
              } else {
                res.status(200).send("User created successfully");
              }
            }
          );
        } catch (hashError) {
          console.error(hashError);
          res.status(500).send("Error hashing the password");
        }
      }
    }
  );
});

// API 2: User Login
app.post("/login/", async (req, res) => {
  const { username, password } = req.body;

  // Check if the user exists
  db.get(
    "SELECT * FROM user WHERE username = ?",
    [username],
    async (err, row) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else if (!row) {
        res.status(400).send("Invalid user");
      } else {
        // Check if the provided password is correct using bcrypt
        const passwordMatch = await bcrypt.compare(password, row.password);

        if (passwordMatch) {
          // Generate and return a JWT token
          const jwtToken = jwt.sign({ userId: row.user_id }, "secretKey");
          res.status(200).json({ jwtToken });
        } else {
          res.status(400).send("Invalid password");
        }
      }
    }
  );
});

// Middleware for JWT authentication
function authenticateToken(req, res, next) {
  const token = req.header("Authorization");

  if (!token) {
    res.status(401).send("Invalid JWT Token");
    return;
  }

  jwt.verify(token, "secretKey", (err, user) => {
    if (err) {
      res.status(401).send("Invalid JWT Token");
      return;
    }
    req.user = user;
    next();
  });
}

// API 3: Get User's Feed
app.get("/user/tweets/feed/", authenticateToken, (req, res) => {
  const userId = req.user.userId;

  // Query to retrieve tweets from users followed by the logged-in user
  db.all(
    `SELECT u.username, t.tweet, t.date_time 
   FROM follower AS f
   JOIN tweet AS t ON t.user_id = f.following_user_id
   JOIN user AS u ON u.user_id = t.user_id
   WHERE f.follower_user_id = ? 
   ORDER BY t.date_time DESC LIMIT 4`,
    [userId],
    (err, rows) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else {
        res.status(200).json(rows);
      }
    }
  );
});

// API 4: Get User's Following List
app.get("/user/following/", authenticateToken, (req, res) => {
  const userId = req.user.userId;

  // Query to retrieve the list of users followed by the logged-in user
  db.all(
    `SELECT u.name
     FROM follower AS f
     JOIN user AS u ON u.user_id = f.following_user_id
     WHERE f.follower_user_id = ?`,
    [userId],
    (err, rows) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else {
        const followingList = rows.map((row) => row.name);
        res.status(200).json({ followingList });
      }
    }
  );
});

// API 5: Get User's Followers List
app.get("/user/followers/", authenticateToken, (req, res) => {
  const userId = req.user.userId;

  // Query to retrieve the list of users following the logged-in user
  db.all(
    `SELECT u.name
     FROM follower AS f
     JOIN user AS u ON u.user_id = f.follower_user_id
     WHERE f.following_user_id = ?`,
    [userId],
    (err, rows) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else {
        const followersList = rows.map((row) => row.name);
        res.status(200).json({ followersList });
      }
    }
  );
});

// API 6: Get Tweet by Tweet ID
app.get("/tweets/:tweetId", authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const tweetId = req.params.tweetId;

  // Check if the tweet belongs to a user followed by the logged-in user
  db.get(
    `SELECT t.tweet, 
            (SELECT COUNT(*) FROM like WHERE tweet_id = ?) AS likes,
            (SELECT COUNT(*) FROM reply WHERE tweet_id = ?) AS replies,
            t.date_time
     FROM tweet AS t
     JOIN follower AS f ON t.user_id = f.following_user_id
     WHERE t.tweet_id = ? AND f.follower_user_id = ?`,
    [tweetId, tweetId, tweetId, userId],
    (err, row) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else if (!row) {
        res.status(401).send("Invalid Request");
      } else {
        res.status(200).json(row);
      }
    }
  );
});

// API 7: Get Likes for a Tweet
app.get("/tweets/:tweetId/likes", authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const tweetId = req.params.tweetId;

  // Check if the tweet belongs to a user followed by the logged-in user
  db.get(
    `SELECT t.tweet_id
     FROM tweet AS t
     JOIN follower AS f ON t.user_id = f.following_user_id
     WHERE t.tweet_id = ? AND f.follower_user_id = ?`,
    [tweetId, userId],
    (err, row) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else if (!row) {
        res.status(401).send("Invalid Request");
      } else {
        // Query to retrieve usernames who liked the tweet
        db.all(
          `SELECT u.username
           FROM like AS l
           JOIN user AS u ON u.user_id = l.user_id
           WHERE l.tweet_id = ?`,
          [tweetId],
          (err, rows) => {
            if (err) {
              console.error(err);
              res.status(500).send("Internal Server Error");
            } else {
              const likes = rows.map((row) => row.username);
              res.status(200).json({ likes });
            }
          }
        );
      }
    }
  );
});

// API 8: Get Replies for a Tweet
app.get("/tweets/:tweetId/replies", authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const tweetId = req.params.tweetId;

  // Check if the tweet belongs to a user followed by the logged-in user
  db.get(
    `SELECT t.tweet_id
     FROM tweet AS t
     JOIN follower AS f ON t.user_id = f.following_user_id
     WHERE t.tweet_id = ? AND f.follower_user_id = ?`,
    [tweetId, userId],
    (err, row) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else if (!row) {
        res.status(401).send("Invalid Request");
      } else {
        // Query to retrieve replies for the tweet
        db.all(
          `SELECT u.name, r.reply
           FROM reply AS r
           JOIN user AS u ON u.user_id = r.user_id
           WHERE r.tweet_id = ?`,
          [tweetId],
          (err, rows) => {
            if (err) {
              console.error(err);
              res.status(500).send("Internal Server Error");
            } else {
              // Respond with tweet and list of replies
              const tweetAndReplies = {
                tweet: rows[0], // Assuming there is only one tweet with the given ID
                replies: rows.slice(1), // Exclude the first row (tweet) from replies
              };
              res.status(200).json(tweetAndReplies);
            }
          }
        );
      }
    }
  );
});

// API 9: Get User's Tweets
app.get("/user/tweets", authenticateToken, (req, res) => {
  const userId = req.user.userId;

  // Query to retrieve all tweets of the logged-in user
  db.all(
    `SELECT t.tweet, 
            (SELECT COUNT(*) FROM like WHERE tweet_id = t.tweet_id) AS likes,
            (SELECT COUNT(*) FROM reply WHERE tweet_id = t.tweet_id) AS replies,
            t.date_time
     FROM tweet AS t
     WHERE t.user_id = ?`,
    [userId],
    (err, rows) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else {
        res.status(200).json(rows);
      }
    }
  );
});

// API 10: Create a Tweet
app.post("/user/tweets", authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const { tweet } = req.body;

  // Insert the new tweet into the tweet table
  db.run(
    "INSERT INTO tweet (tweet, user_id, date_time) VALUES (?, ?, datetime('now'))",
    [tweet, userId],
    (err) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else {
        // Updated response to match specified error message
        res.status(200).send("Created a Tweet");

        // Optionally, you can perform additional actions or logging here
      }
    }
  );
});

// API 11: Delete a Tweet
app.delete("/tweets/:tweetId", authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const tweetId = req.params.tweetId;

  // Check if the tweet belongs to the logged-in user
  db.get(
    "SELECT * FROM tweet WHERE tweet_id = ? AND user_id = ?",
    [tweetId, userId],
    (err, row) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else if (!row) {
        // If the tweet doesn't belong to the user, return 401 and 'Invalid Request'
        res.status(401).send("Invalid Request");
      } else {
        // Delete the tweet
        db.run("DELETE FROM tweet WHERE tweet_id = ?", [tweetId], (err) => {
          if (err) {
            console.error(err);
            res.status(500).send("Internal Server Error");
          } else {
            // Respond with success and update the database
            res.status(200).send("Tweet Removed");

            // Optionally, you can perform additional actions or logging here
          }
        });
      }
    }
  );
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

module.exports = app;
