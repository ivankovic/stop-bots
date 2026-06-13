//! End-to-end tests for stop-bots.
//!
//! These tests use a fake filesystem (via tempfile) to test the application
//! in a hermetic environment. Each test:
//! 1. Sets up the fake filesystem with nginx configs
//! 2. Runs the app with command-line flags to trigger actions
//! 3. Verifies the results by checking the database
//!
//! Tests NEVER invoke code in src directly, except to run the app as a subprocess.

use anyhow::Result;

mod test_harness;
use stop_bots::db::Database;
use test_harness::{
    create_nginx_main_config, create_nginx_site_config, generate_random_site_name,
    setup_test_with_site, TestContext,
};

/// The first e2e test: Create fake filesystem with nginx config, run app, check DB contains site.
///
/// Test flow:
/// 1. Generate random site name
/// 2. Create fake filesystem with nginx config for the site
/// 3. Start the app with --scan-sites flag and environment variables
/// 4. The app discovers sites and stores them in DB
/// 5. Stop the app
/// 6. Verify the DB contains the site
#[test]
fn test_e2e_nginx_site_discovery() -> Result<()> {
    // 1. Generate random site name for this test run
    let site_name = generate_random_site_name();
    println!("Testing with randomly generated site: {}", site_name);

    // 2. Create test context with fake filesystem and nginx config
    let ctx = setup_test_with_site(&site_name)?;

    // 3. Start the app with --scan-sites flag
    let app = ctx.start_app_with_scan()?;

    // 4. Wait for the scan to complete
    app.wait_for_processing(std::time::Duration::from_secs(2));

    // 5. Stop the app
    app.stop()?;

    // 6. Verify the DB contains our site
    let mut db = Database::open(&ctx.db_path)?;
    db.initialize()?;
    let sites = db.get_all_sites()?;

    let site_found = sites.iter().any(|s| s.name == site_name);
    assert!(
        site_found,
        "Expected to find site '{}' in the database",
        site_name
    );

    println!(
        "✓ Test passed: Site '{}' was discovered and stored in DB",
        site_name
    );

    Ok(())
}

/// Test that multiple sites are discovered correctly.
#[test]
fn test_e2e_multiple_sites_discovery() -> Result<()> {
    // Create context
    let ctx = TestContext::new()?;

    // Add multiple sites with random names
    let site1_name = generate_random_site_name();
    let site2_name = generate_random_site_name();

    ctx.filesystem
        .add_nginx_main_config(&create_nginx_main_config())?;
    ctx.filesystem.add_site_config(
        &format!("{}.conf", site1_name),
        &create_nginx_site_config(&site1_name),
    )?;
    ctx.filesystem.add_site_config(
        &format!("{}.conf", site2_name),
        &create_nginx_site_config(&site2_name),
    )?;

    // Start the app with --scan-sites
    let app = ctx.start_app_with_scan()?;
    app.wait_for_processing(std::time::Duration::from_secs(2));

    // Stop the app
    app.stop()?;

    // Verify the DB contains both sites
    let mut db = Database::open(&ctx.db_path)?;
    db.initialize()?;
    let sites = db.get_all_sites()?;

    let site1_found = sites.iter().any(|s| s.name == site1_name);
    let site2_found = sites.iter().any(|s| s.name == site2_name);

    assert!(
        site1_found,
        "Expected to find site {} in database",
        site1_name
    );
    assert!(
        site2_found,
        "Expected to find site {} in database",
        site2_name
    );

    println!(
        "✓ Multiple sites test passed: Found {} sites in DB",
        sites.len()
    );

    Ok(())
}
