// REPL bootstrap — exposes rpc.exports.eval(code) so the backend can evaluate
// arbitrary user-supplied JS in the target process and capture the result as
// a string. Errors return "Error: <message>". All console.log/send() calls
// continue to flow through the normal session message channel.
rpc.exports = {
    eval: function (code) {
        try {
            var result = (0, eval)(code);
            if (result === undefined) return "undefined";
            if (result === null) return "null";
            if (typeof result === "object") {
                try { return JSON.stringify(result); }
                catch (e) { return String(result); }
            }
            return String(result);
        } catch (e) {
            return "Error: " + (e && e.message ? e.message : String(e));
        }
    }
};
