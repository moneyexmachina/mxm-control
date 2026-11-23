/**
 * Bootstrap or verify the MXM MongoDB administrator.
 *
 * Executed by mongosh inside the mxm-dev MongoDB container.
 *
 * Credentials arrive as a JSON object on standard input:
 *   { "username": "...", "password": "..." }
 *
 * The script creates the first administrator using MongoDB's
 * localhost exception, or verifies an existing administrator.
 *
 * It never changes an existing user's password or roles.
 * Diagnostics deliberately exclude credential values.
 */

"use strict";

await (async () => {
  /**
   * Abort with a stage-specific, credential-free diagnostic.
   *
   * @param {string} stage - Operation that failed.
   * @param {unknown} [error] - Optional MongoDB error.
   * @returns {never}
   */
  function fail(stage, error) {
    const code = Number.isInteger(error?.code)
      ? String(error.code)
      : "unknown";

    print(`ERROR: stage=${stage} code=${code}`);
    quit(1);
  }

  let credentials;

  try {
    credentials = JSON.parse(
      require("node:fs").readFileSync(0, "utf8")
    );
  } catch (error) {
    fail("credential_input", error);
  }

  if (
    credentials.username !== "mxm-admin" ||
    typeof credentials.password !== "string" ||
    credentials.password.length === 0
  ) {
    fail("credential_validation");
  }

  const admin = db.getSiblingDB("admin");
  let authenticated = false;
  let created = false;

  // First attempt to authenticate the existing administrator.
  try {
    authenticated =
      (await admin.auth(
        credentials.username,
        credentials.password
      )) === 1;
  } catch (error) {
    if (
      error?.code !== 18 &&
      error?.codeName !== "AuthenticationFailed"
    ) {
      fail("authenticate_existing", error);
    }
  }

  let verificationDb = admin;

  if (!authenticated) {
    // First-user creation is possible only while the localhost
    // exception is active. An existing user is never overwritten.
    try {
      await admin.createUser({
        user: credentials.username,
        pwd: credentials.password,
        roles: [{ role: "root", db: "admin" }]
      });

      created = true;
    } catch (error) {
      fail("create_user", error);
    }

    // Verify using a fresh MongoDB connection rather than the
    // bootstrap connection.
    try {
      verificationDb = new Mongo(
        "mongodb://127.0.0.1:27017"
      ).getDB("admin");

      authenticated =
        (await verificationDb.auth(
          credentials.username,
          credentials.password
        )) === 1;
    } catch (error) {
      fail("authenticate_after_creation", error);
    }

    if (!authenticated) {
      fail("authenticate_after_creation");
    }
  }

  // Verify the effective administrator role.
  let status;

  try {
    status = await verificationDb.runCommand({
      connectionStatus: 1
    });
  } catch (error) {
    fail("verify_roles", error);
  }

  const roles = status.authInfo?.authenticatedUserRoles ?? [];

  const hasRootRole = roles.some(
    role => role.role === "root" && role.db === "admin"
  );

  if (status.ok !== 1 || !hasRootRole) {
    fail("verify_root_role");
  }

  print(
    created
      ? "OK: MongoDB administrator created and verified"
      : "OK: MongoDB administrator already present and verified"
  );
})().catch(() => {
  print("ERROR: stage=unexpected code=unknown");
  quit(1);
});
