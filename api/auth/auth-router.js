const router = require("express").Router();
const { usernameVarmi, rolAdiGecerlimi } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // bu secret'ı kullanın!
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const userModel = require("../users/users-model");

router.post("/register", rolAdiGecerlimi, async (req, res, next) => {
  let user = req.body;

  const hash = bcrypt.hashSync(user.password, 8);
  user.password = hash;
  try {
    let insertedUser = await userModel.ekle(user);
    res.status(201).json(insertedUser);
  } catch (error) {
    next(error);
  }
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status: 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});

router.post("/login", usernameVarmi, async (req, res, next) => {
  try {
    let { username, password } = req.body;
    const user = await userModel.goreBul({ username });
    if (user.length > 0 && bcrypt.compareSync(password, user[0].password)) {
      const token = generatetoken(user[0]);
      res.json({ message: `${user[0].username} geri geldi!`, token });
    } else {
      next({ status: 401, message: `Geçersiz kriter` });
    }
  } catch (error) {
    next(error);
  }

  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status: 200
    {
      "message": "sue geri geldi!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    Token 1 gün sonra timeout olmalıdır ve aşağıdaki bilgiyi payloadında içermelidir:

    {
      "subject"  : 1       // giriş yapan kullanıcının user_id'si
      "username" : "bob"   // giriş yapan kullanıcının username'i
      "role_name": "admin" // giriş yapan kulanıcının role adı
    }
   */
});

function generatetoken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role,
  };
  const options = {
    expiresIn: "1d",
  };
  const token = jwt.sign(payload, JWT_SECRET, options);
  return token;
}

module.exports = router;
