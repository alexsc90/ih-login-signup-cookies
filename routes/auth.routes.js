/* eslint-disable space-before-blocks */
// IMPORTACIONES
const express = require('express')
const router = express.Router()
const bcryptjs = require('bcryptjs')
const mongoose = require('mongoose')


const User = require('../models/User.model')

const saltRounds = 10

// GET Formulario Signup
router.get('/signup', (req, res) => res.render('auth/signup'));

// POST Formulario enviado al backend

router.post('/signup', (req,res,next) => {
  const { username, email, password } = req.body;

  // VALIDACIÓN DE QUE LOS INPUTS ESTÉN LLENOS Y NO VACÍOS
  if( !username || !email || !password) {
    res.render('auth/signup', {errorMessage: "Todos los campos son obligatorios"})
    return 
  }

  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;

  if(!regex.test(password)) {
    res.status(500).render('auth/signup', {errorMessage: 'El password debe de cumplir con más de 6 caracteres, contener al menos un número, una minúscula y una mayúscula.'})
    return
  }

  // AUTENTICACIÓN
    bcryptjs
    .genSalt(saltRounds)
    .then((salt) => {
        return bcryptjs.hash(password, salt)
    })
    .then((hashedPassword) => {
      return User.create({
        username: username,
        email: email,
        passwordHash: hashedPassword
      })
    })
    .then((usuario) => {
      console.log(usuario)
      res.redirect('/login')
    })
    .catch((error) => {
      // VALIDACIÓN DE CORREO ELECTRÓNICO
          if(error instanceof mongoose.Error.ValidationError) {
            res.status(500).render('auth/signup', {errorMessage: 'El correo electrónico no tiene el formato adecuado'})
          } else if (error.code === 11000) {
            // VALIDACIÓN DE UNICIDAD
            res.status(500).render('auth/signup', {
              errorMessage: 'El usuario y el correo deben ser únicos. Puede que el usuario o el correo que insertaste ya están siendo usados.'
            })
          } else { // ERROR DE CUALQUIER TIPO
            next(error) 
          }
    })
})


//  GET Formulario Login

router.get('/login', (req, res, next) => {
  res.render("auth/login")
})

// POST Formulario Login

router.post('/login', (req, res, next) => {
  const { email, password } = req.body

  console.log("Sessión ===>", req.session)

  // VALIDAR QUE NO TENGAMOS INPUTS VACÍOS
  if(email === "" || password === ""){
      res.render('auth/login', 
      {
        errorMessage: "Por favor, ingresa ambos campos. No dejes vacío ninguno."
      }
    )
  }

  // BÚSQUEDA DENTRO DE LA BASE DE DATOS PARA VERIFICAR QUE EXISTA EL EMAIL DEL USUARIO EN NUESTRA BASE DE DATOS
  User.findOne({email})
    .then((usuarioEncontrado) => {
      
      // SI EL USUARIO NO FUE ENCONTRADO, ENVIAR MENSAJE DE ERROR.
      if (!usuarioEncontrado) {
        res.render('auth/login', {
          errorMessage: "El email no está registrado. Intenta con otro o regístrate."
        })
        return
      }

                          // true o un false    
                                    // pass formulario ,  pass base de datos
      else if (bcryptjs.compareSync(password, usuarioEncontrado.passwordHash)) {
          // res.render('users/userProfile', {user: usuarioEncontrado})
          req.session.currentUser = usuarioEncontrado
          res.redirect('/userProfile')
      } else { // SI SALIÓ FALSE, el password no coincidió, mandar mensaje de error
          res.render('auth/login', {errorMessage: 'Password incorrecto'})
      }

    })
    .catch((e) => console.log(e))

})






// router.post('/signup', async (req,res,next) => {
//   const { username, email, password } = req.body;


//   try {
//     const genSaltResult   = await bcrypt.genSalt(saltRounds)
//     const hashPassword    = await bcrypt.hash(password, genSaltResult)

//     await User.create({
//       username: username,
//       email: email,
//       passwordHash: hashPassword
//     })  

//     await res.redirect("/userProfile")
//   } catch(error) {
//     console.log(error)
//   }
// })


router.post('/logout', (req,res,next) => {
  req.session.destroy()
  res.redirect('/')
})


router.get('/privado',(req, res, next) => {
  console.log(req.session)
  if(req.session.currentUser){
    res.render("privado")
    return
  }

  return res.send("No estas loggeado")
})

// GET Perfil del usuario
router.get('/userProfile', (req, res) => {
  res.render('users/user-profile', {
    valorGalleta: req.session.currentUser
  })
});



module.exports = router;