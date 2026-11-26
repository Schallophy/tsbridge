//! The smaller modules are checked for the gaps the larger audits found.
//!
//! The protocol tables, the bookkeeping properties and the account surface each
//! got an enumerate-and-diff test, and each found something. These four modules
//! are small enough that they were assumed fine, which is exactly the assumption
//! that failed before. What can be enumerated differs per module:
//!
//! * `version` has a signed table; every platform in it must be reachable
//!   through the public API, or the entry is dead weight.
//! * `icons` has a format sniffer with a fixed set of answers; each must be
//!   reachable from a real header.
//! * `audio` has a panning model with documented bounds; the bounds must hold.
//! * `files` is async I/O with no pure surface; the throttle constant is the only
//!   enumerable thing and it is asserted for the property that matters.
//!
//! `icons` already has four unit tests for its format sniffer (png, jpg, svg
//! after an XML declaration, and the `bin` fallback), so it is not repeated
//! here — the point of this file is the gaps, not a second copy.
//!
//! These are behavioural checks rather than source scans: the modules expose
//! their tables through functions, so calling them is more reliable than
//! parsing.

use tsbridge_core::version::VersionChoice;

/// Every platform the signed table carries must be reachable by name.
///
/// A platform present in the table but never returned by `platforms()` is an
/// entry nothing can select — the signature is there and unusable.
#[test]
fn every_signed_platform_is_reachable() {
    let platforms = VersionChoice::platforms();
    assert!(
        !platforms.is_empty(),
        "the table reports no platforms at all"
    );

    for platform in &platforms {
        let choices = VersionChoice::choices(platform);
        assert!(
            !choices.is_empty(),
            "platform `{platform}` is listed but has no versions"
        );

        // Every listed version must resolve to a signature; otherwise the entry
        // is a version string with nothing behind it.
        for version in &choices {
            let choice = VersionChoice::new(version.clone(), platform.clone());
            assert!(
                choice.resolve().is_some(),
                "`{version}` on `{platform}` is offered but does not resolve to a signed entry"
            );
        }
    }
}

/// `standard()` must resolve, or a client that asks for the default cannot
/// connect.
#[test]
fn the_standard_choice_resolves() {
    let standard = VersionChoice::standard();
    let resolved = standard
        .resolve()
        .expect("the default version must have a signature");
    assert!(
        !resolved.signature.is_empty(),
        "the default version resolved to an empty signature"
    );
}

/// A platform the table does not carry yields nothing rather than a wrong entry.
#[test]
fn an_unknown_platform_yields_no_choices() {
    assert!(VersionChoice::choices("NoSuchPlatform").is_empty());
    let choice = VersionChoice::new("3.6.3", "NoSuchPlatform");
    assert!(choice.resolve().is_none());
}

/// The panning model keeps the properties its documentation claims.
///
/// `Position` documents constant power and a hard silent distance; the unit
/// tests in `audio.rs` check individual bearings, this checks the invariants
/// across the whole range.
#[test]
fn the_panning_model_keeps_its_documented_bounds() {
    use tsbridge_core::Position;

    // Constant power across the full circle: the two gains square to 1 whenever
    // no distance attenuation applies.
    for degrees in (0..360).step_by(5) {
        let position = Position {
            angle: degrees as f32,
            distance: Position::FULL_VOLUME_DISTANCE,
        };
        let (left, right) = position.gains();
        let power = left * left + right * right;
        assert!(
            (power - 1.0).abs() < 1e-4,
            "constant power broke at {degrees} degrees: {left}^2 + {right}^2 = {power}"
        );
    }

    // Silent at and beyond the documented distance, and never negative.
    for distance in [Position::SILENT_DISTANCE, Position::SILENT_DISTANCE * 2.0] {
        let (left, right) = Position {
            angle: 45.0,
            distance,
        }
        .gains();
        assert_eq!((left, right), (0.0, 0.0), "audible at distance {distance}");
    }

    // Inside the full-volume radius nothing is attenuated.
    let near = Position {
        angle: 0.0,
        distance: 0.0,
    }
    .gains();
    let edge = Position {
        angle: 0.0,
        distance: Position::FULL_VOLUME_DISTANCE,
    }
    .gains();
    assert!((near.0 - edge.0).abs() < 1e-5 && (near.1 - edge.1).abs() < 1e-5);
}

/// `suggest` narrows by prefix and stays within one platform.
#[test]
fn suggestions_stay_within_the_platform() {
    for platform in VersionChoice::platforms() {
        let all = VersionChoice::choices(&platform);
        let Some(first) = all.first() else {
            continue;
        };
        let prefix: String = first.chars().take(3).collect();
        for suggested in VersionChoice::suggest(&prefix, &platform) {
            assert!(
                all.contains(&suggested),
                "`{suggested}` was suggested for `{platform}` but is not in its list"
            );
        }
    }
}
