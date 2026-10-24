// "nodemon" is declared under devDependencies, but the project's own
// "start" script (what actually runs in production) invokes it directly.
// A clean --omit=dev install would not have nodemon available at all,
// so `npm start` would fail in a production-only environment.
console.log("server running");
