# Upgrading

## Incorporating Catalyst upstream changes

Shipmate's maintained branch is based on Catalyst commit
`de0f1505c1470823e7f286586d88ee1f28c364bf`. Keep an `upstream` remote pointing
to `https://github.com/catalyst/moodle-auth_saml2.git`. Review upstream commits,
licenses, dependency changes, and Moodle compatibility before incorporating
them. Merge or cherry-pick reviewed changes onto `MOODLE_502_STABLE`, retain
Catalyst attribution, run all PHPUnit and Behat jobs, and record the new
upstream base here when the accepted baseline changes. Shipmate-specific
behavior must not be presented as Catalyst-maintained.

Older branches have simplesamlphp included in `.extlib` folder, see `UPGRADE.md` in that folder for instructions.

Newer versions we are using composer to install and update simplesamlphp, which is what the rest of this section is about.

There has been a `Dockerfile` and `docker-compose.yaml` added to allow running composer update consistently without relying on local configuration of php.

To run an upgrade running `docker compose up` will start the container and run `composer update --no-dev`. You can then commit the result with the updated `vendor` folder and updated `composer.lock` file.


# Patches
We are using composer patches to manage any changes needed for simplesamlphp, or any other composer packages. To do this you must generate a [git patch](https://git-scm.com/docs/git-format-patch), add it to the `patches/` folder, and reference it in the list in `composer.json`.
