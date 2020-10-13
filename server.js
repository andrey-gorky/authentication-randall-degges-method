const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const sessions = require("client-sessions");
const bcrypt = require("bcryptjs");
const csurf = require("csurf"); 						// CSRF Protection package

mongoose.connect("mongodb://localhost/auth_test2", {
	useNewUrlParser: true,
	useUnifiedTopology: true,
	useFindAndModify: false
});
let app = express();



app.use(bodyParser.urlencoded({ extended: true }));
app.use(sessions({
	cookieName: "session",
	secret: "a1s2d3f4g5h6j7k8",
	duration: 30 * 60 * 1000,				// 30 mins

	//* Дальше дополнительные опции
	activeDuration: 5 * 60 * 1000,	// 5 mins
	httpOnly: true,									// Не позволяет JS коду иметь доступ к кукисам
	secure: true,										// Отправляет кукисы только через https
	ephemeral: true									// удаляет кукисы после закрытия браузера
}));
app.use(csurf());


// Middleware функция, которая проверяет авторизов ли пользователь
app.use((req, res, next) => {
	//Если нет кукис и/или даных о сессии в кукис => функция некст()
	if (!(req.session && req.session.userId)) {
		return next();
	}

	//Если сессия идёт, берём ID пользователя из сессии
	User.findById(req.session.userId, (err, user) => {
		if (err) {
			return next(err);
		}

		if (!user) {
			return next();
		}

		// Перезаписывается данные пароля, чтоб случайно его никуда не вывести, напрмер, и тд и тп
		user.password = undefined;

		req.user = user;
		// Специфика express. Открываем доступ к обьекту user в том числе и в шаблонах pug.
		res.locals.user = user;

		next();

	});
});



//================================
//* User Model
var User = mongoose.model("User", new mongoose.Schema({
	firstName: { type: String, required: true },
	lastName: { type: String, required: true },
	email: { type: String, required: true, unique: true },
	password: { type: String, required: true }
}));
//================================


app.get("/", (req, res) => {
	res.render("index.pug", { csrfToken: req.csrfToken() });
});



app.get("/register", (req, res) => {
	res.render("register.pug", { csrfToken: req.csrfToken() });
});

//===================================
app.post("/register", (req, res) => {
	let hash = bcrypt.hashSync(req.body.password, 14);
	//* Define hash and use .hachSync method. 14 - is bcrypt work factor (tells bcrypt how strong this hash would be).
	req.body.password = hash;
	let user = new User(req.body);

	user.save((err) => {
		if (err) {
			let error = "Something went wrong! Please try again.";

			if (err === 11000) {
				error = "That email is already taken, please try another.";
			}

			return res.render("register.pug", { csrfToken: req.csrfToken(), error: error });
		}

		res.redirect("/dashboard");
	});
});
//===================================




app.get("/login", (req, res) => {
	res.render("login.pug", { csrfToken: req.csrfToken() });
});

//===================================
app.post("/login", (req, res) => {
	User.findOne({ email: req.body.email }, (err, user) => {
		// if (err || !user || req.body.password !== user.password) {  (without bcrypt npm)
		if (err || !user || !bcrypt.compareSync(req.body.password, user.password)) {
			return res.render("login.pug", {
				csrfToken: req.csrfToken(),
				error: "Incorrect email/password."
			});
		}

		req.session.userId = user._id;

		res.redirect("/dashboard");
	});
});
//==================================




//==================================
app.get("/logout", (req, res, next) => {
	req.session.reset();
	res.redirect("/");
});
//==================================



app.get("/dashboard", loginRequired, (req, res, next) => {
	if (!(req.session && req.session.userId)) {
		return res.redirect("/login");
	}

	User.findById(req.session.userId, (err, user) => {
		if (err) {
			return next(err);
		}

		if (!user) {
			return res.redirect("/login");
		}

		res.render("dashboard.pug", { csrfToken: req.csrfToken() });
	});
});

//=======================================
//MIDDLEWARES
function loginRequired(req, res, next) {
	if (!req.user) {
		return res.redirect("/login");
	}
	next();
}
//=======================================

app.listen(3000, () => {
	console.log("Server is running...");
});