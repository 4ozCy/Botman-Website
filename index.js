require('dotenv').config();
const Koa = require('koa');
const Router = require('@koa/router');
const session = require('koa-session');
const bodyParser = require('koa-bodyparser');
const mongoose = require('mongoose');
const passport = require('passport');
const { Strategy: DiscordStrategy } = require('passport-discord');
const axios = require('axios');
const serve = require('koa-static');
const path = require('path');

const app = new Koa();
const router = new Router();

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

app.keys = [process.env.SESSION_SECRET];
app.use(session({}, app));
app.use(bodyParser());
app.use(passport.initialize());
app.use(passport.session());

app.use(serve(path.join(__dirname, 'public')));

passport.use(new DiscordStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: process.envREDIRECT_URI,
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

router.get('/auth/discord', passport.authenticate('discord'));

router.get('/auth/discord/callback',
  passport.authenticate('discord', { failureRedirect: '/' }),
  (ctx) => {
    ctx.redirect('/dashboard');
  }
);

router.get('/dashboard', async (ctx) => {
  if (!ctx.isAuthenticated()) {
    return ctx.redirect('/');
  }
  ctx.body = `Welcome, ${ctx.state.user.username}`;
});

router.get('/logout', (ctx) => {
  ctx.logout();
  ctx.redirect('/');
});

router.post('/site/add', async (ctx) => {
  if (!ctx.isAuthenticated()) {
    ctx.status = 401;
    ctx.body = 'Unauthorized';
    return;
  }

  const { url } = ctx.request.body;

  const newSite = new Site({
    userId: ctx.state.user._id,
    url,
    status: 'Unknown',
    lastChecked: new Date(),
  });

  await newSite.save();
  ctx.body = { message: 'Site added for monitoring', site: newSite };
});

router.get('/site/get-sites', async (ctx) => {
  if (!ctx.isAuthenticated()) {
    ctx.status = 401;
    ctx.body = 'Unauthorized';
    return;
  }

  const sites = await Site.find({ userId: ctx.state.user._id });
  ctx.body = sites;
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

app.use(router.routes()).use(router.allowedMethods());

app.listen(5000, () => {
  console.log('Server running on http://localhost:5000');
});
