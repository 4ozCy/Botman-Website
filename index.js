require('dotenv').config();
const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const passport = require('passport');
const { Strategy: DiscordStrategy } = require('passport-discord');
const axios = require('axios');
const path = require('path');

const app = express();
const port = 8080;

mongoose.connect(process.env.MONGODB_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const UserSchema = new mongoose.Schema({
  discordId: String,
  username: String,
  email: String,
  avatar: String,
});

const SiteSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  url: String,
  status: String,
  lastChecked: Date,
  uptime: { type: Number, default: 0 },
  downtime: { type: Number, default: 0 }
});

const User = mongoose.model('User', UserSchema);
const Site = mongoose.model('Site', SiteSchema);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URL }),
  cookie: {
    maxAge: 168 * 60 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
  },
}));

app.use(express.static(path.join(__dirname, 'public')));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new DiscordStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: process.env.REDIRECT_URI,
  scope: ['identify', 'email'],
}, async (accessToken, refreshToken, profile, done) => {
  let user = await User.findOne({ discordId: profile.id });

  if (user) {
    user.username = profile.username;
    user.email = profile.email;
    user.avatar = profile.avatar;
    await user.save();
  } else {
    user = new User({
      discordId: profile.id,
      username: profile.username,
      email: profile.email,
      avatar: profile.avatar,
    });
    await user.save();
  }

  return done(null, user);
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

app.get('/auth/discord', passport.authenticate('discord'));

app.get('/auth/discord/callback', 
  passport.authenticate('discord', { failureRedirect: '/' }), 
  (req, res) => {
    res.redirect('/dashboard');
  }
);

app.get('/dashboard', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect('/');
  });
});

app.post('/site/add', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  const { url } = req.body;

  const newSite = new Site({
    userId: req.user._id,
    url,
    status: 'Unknown',
    lastChecked: new Date(),
  });

  await newSite.save();
  res.json({ message: 'Site added for monitoring', site: newSite });
});

app.get('/site/get-sites', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  const sites = await Site.find({ userId: req.user._id });
  res.json(sites);
});

async function checkSiteStatus(site) {
  try {
    const start = Date.now();
    const response = await axios.get(site.url);
    const ping = Date.now() - start;
    const newStatus = response.status === 200 ? 'UP' : 'DOWN';

    if (site.status !== newStatus) {
      site.status = newStatus;
      site.ping = ping;
      site.lastChecked = new Date();
      await site.save();
    }
  } catch (error) {
    const newStatus = 'DOWN';

    if (site.status !== newStatus) {
      site.status = newStatus;
      site.ping = null;
      site.lastChecked = new Date();
      await site.save();
    }
  }
}

function monitorSites() {
  Site.find({}, (err, sites) => {
    if (err) return console.error(err);
    sites.forEach(site => checkSiteStatus(site));
  });
}

setInterval(monitorSites, 2 * 60 * 1000);

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
