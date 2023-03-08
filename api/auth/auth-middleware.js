const { JWT_SECRET } = require("../secrets"); // bu secreti kullanın!
const jwt = require("jsonwebtoken");
const userModel = require("../users/users-model");

const sinirli = (req, res, next) => {
  const token = req.headers.authorization;

  if (token) {
    jwt.verify(token, JWT_SECRET, (err, decodedJWT) => {
      if (err) {
        next({ status: 401, message: "Token gecersizdir" });
      } else {
        req.userInfo = decodedJWT;
        next();
      }
    });
  } else {
    next({ status: 401, message: "Token gereklidir" });
  }

  /*
    Eğer Authorization header'ında bir token sağlanmamışsa:
    status: 401
    {
      "message": "Token gereklidir"
    }

    Eğer token doğrulanamıyorsa:
    status: 401
    {
      "message": "Token gecersizdir"
    }

    Alt akıştaki middlewarelar için hayatı kolaylaştırmak için kodu çözülmüş tokeni req nesnesine koyun!
  */
};

const sadece = (role_name) => (req, res, next) => {
  if (req.headers.authorization && req.userInfo.role_name === role_name) {
    next();
  } else {
    next({ status: 403, message: "Bu, senin için değil" });
  }
  /*
    
	Kullanıcı, Authorization headerında, kendi payloadu içinde bu fonksiyona bağımsız değişken olarak iletilen 
	rol_adı ile eşleşen bir role_name ile bir token sağlamazsa:
    status: 403
    {
      "message": "Bu, senin için değil"
    }

    Tekrar authorize etmekten kaçınmak için kodu çözülmüş tokeni req nesnesinden çekin!
  */
};

const usernameVarmi = async (req, res, next) => {
  try {
    let filteredUsers = await userModel.goreBul({
      username: req.body.username,
    });
    if (filteredUsers.length > 0) {
      next();
    } else {
      next({ status: 401, message: "Geçersiz kriter" });
    }
  } catch (error) {
    next(err);
  }

  /*
    req.body de verilen username veritabanında yoksa
    status: 401
    {
      "message": "Geçersiz kriter"
    }
  */
};

const rolAdiGecerlimi = (req, res, next) => {
  const { role_name } = req.body;
  if (!role_name || role_name.trim() === "") {
    req.body.role_name = "student";
    next();
  } else {
    if (role_name.trim() === "admin") {
      next({ status: 422, message: "Rol adı admin olamaz" });
    } else if (role_name.trim().length > 32) {
      next({ status: 422, message: "32 karakterden fazla" });
    } else {
      req.body.role_name = role_name.trim();
      next();
    }
  }

  /*
    Bodydeki role_name geçerliyse, req.role_name öğesini trimleyin ve devam edin.

    Req.body'de role_name eksikse veya trimden sonra sadece boş bir string kaldıysa,
    req.role_name öğesini "student" olarak ayarlayın ve isteğin devam etmesine izin verin.

    Stringi trimledikten sonra kalan role_name 'admin' ise:
    status: 422
    {
      "message": "Rol adı admin olamaz"
    }

    Trimden sonra rol adı 32 karakterden fazlaysa:
    status: 422
    {
      "message": "rol adı 32 karakterden fazla olamaz"
    }
  */
};

module.exports = {
  sinirli,
  usernameVarmi,
  rolAdiGecerlimi,
  sadece,
};
