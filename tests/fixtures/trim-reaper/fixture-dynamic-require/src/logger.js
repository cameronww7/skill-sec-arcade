const config = require("../config.json");

// The logger implementation is chosen at runtime, not compile time: ops
// can swap loggers per-environment by editing config.json alone, no code
// change needed. This is exactly the kind of reference a static import
// sweep cannot resolve, since "winston" never appears as a string
// literal at this call site.
const logger = require(config.loggerName);

module.exports = logger;
