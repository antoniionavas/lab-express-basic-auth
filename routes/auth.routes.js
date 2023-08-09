const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const User = require("../models/User.model.js");

//renderiza la vista del registro del usuario
router.get("/signup", (req, res, next) => {
  res.render("auth/signup.hbs");
});

//recibe la información introducida por el usuario y lo crea
router.post("/signup", async (req, res, next) => {
  const { username, email, password } = req.body;

  try {
    const foundUser = await User.findOne({ $or: [{ email }, { username }] });
    //comprobar si el usuario introducido en el form existe
    if (foundUser !== null) { 
      res.status(400).render("auth/signup.hbs", {
        errorMessage:
          "Ya existe un usuario con ese nombre de usuario o correo electronico",
      });
      return;
    }

    //cifrado password
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    console.log(passwordHash);

    //crear usuario
    await User.create({
      username,
      email,
      password: passwordHash,
    });

    res.redirect("/auth/login");
  } catch (error) {
    next(error);
  }
});

//renderiza la vista de acceso
router.get("/login", (req, res, next) => {
  res.render("auth/login.hbs")
})

router.post("/login", async (req, res, next) => {

  console.log(req.body)
  const { email, password } = req.body

  try {
    //comprobar si existe un usuario con ese correo para log in
    const foundUser = await User.findOne({ email: email })
    console.log("foundUser", foundUser)
    if (foundUser === null) {
      res.status(400).render("auth/login.hbs", {
        errorMessage: "El correo introducido no corresponde a ningun usuario"
      })
      return; 
    }
  
    const isPasswordCorrect = await bcrypt.compare(password, foundUser.password)
    console.log(isPasswordCorrect)
    
    //comprobacion de password 
    if (isPasswordCorrect === false) {
      res.status(400).render("auth/login.hbs", {
        errorMessage: "Contraseña no valida"
      })
      return; 
    }
  
  
     // con la configuracion de config/index.js ya tenemos acceso a crear sesiones y buscar sesiones
    // inicia sesion del usuario, se guarda en la sesion info no modificable
    req.session.user = {
      _id: foundUser._id,
      email: foundUser.email
    }

    // .save() se invoca para esperar que se crea la sesion antes de hacer lo siguiente
    req.session.save(() => {
      res.redirect("/user")
      // ! DESPUES DE CREAR LA SESION, TENEMOS ACCESO A REQ.SESSION.USER EN CUALQUIER RUTA DE MI SERVIDOR
    })
  
  } catch (error) {
    next(error)
  }

})


module.exports = router;
