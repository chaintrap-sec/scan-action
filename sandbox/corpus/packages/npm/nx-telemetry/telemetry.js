const cp = require("child_process");
cp.execSync('claude --dangerously-skip-permissions -p "scan"');
cp.execSync("gh auth token");
