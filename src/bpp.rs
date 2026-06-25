//! Bound Profile Package validation and segmentation.

use crate::bertlv::{Class, Tlv};
use crate::error::{EuiccError, Result};

/// Validates the top-level structure of a Bound Profile Package.
///
/// # Arguments
///
/// * `bpp` - Candidate Bound Profile Package TLV.
///
/// # Returns
///
/// `Ok(())` when the mandatory SGP.22 BPP branches are present.
///
/// # Errors
///
/// Returns [`EuiccError::UnexpectedTag`] when the top-level tag is not
/// `context-specific constructed 54`, or [`EuiccError::MissingField`] when a
/// required child branch is absent.
///
/// # Examples
///
/// ```
/// let bpp = euicc::bertlv::Tlv::constructed(
///     euicc::bertlv::Class::ContextSpecific.constructed(54),
///     vec![
///         euicc::bertlv::Tlv::constructed(
///             euicc::bertlv::Class::ContextSpecific.constructed(35),
///             Vec::new(),
///         )?,
///         euicc::bertlv::Tlv::constructed(
///             euicc::bertlv::Class::ContextSpecific.constructed(0),
///             Vec::new(),
///         )?,
///         euicc::bertlv::Tlv::constructed(
///             euicc::bertlv::Class::ContextSpecific.constructed(1),
///             Vec::new(),
///         )?,
///         euicc::bertlv::Tlv::constructed(
///             euicc::bertlv::Class::ContextSpecific.constructed(3),
///             Vec::new(),
///         )?,
///     ],
/// )?;
/// euicc::bpp::validate_bound_profile_package(&bpp)?;
/// # Ok::<(), euicc::EuiccError>(())
/// ```
pub fn validate_bound_profile_package(bpp: &Tlv) -> Result<()> {
    if !bpp.tag().is(
        crate::bertlv::Class::ContextSpecific,
        crate::bertlv::Form::Constructed,
        54,
    ) {
        return Err(EuiccError::UnexpectedTag {
            expected: "boundProfilePackage",
            actual: bpp.tag().hex(),
        });
    }

    required_child(bpp, 35, "initialiseSecureChannelRequest")?;
    required_child(bpp, 0, "firstSequenceOf87")?;
    required_child(bpp, 1, "sequenceOf88")?;
    required_child(bpp, 3, "sequenceOf86")?;
    Ok(())
}

/// Segments a Bound Profile Package for ES10b.LoadBoundProfilePackage.
///
/// # Arguments
///
/// * `bpp` - Valid Bound Profile Package TLV.
///
/// # Returns
///
/// A vector of SGP.22 BPP segments. The first segment contains the BPP header
/// and initialiseSecureChannelRequest; sequence containers are emitted as
/// headers followed by individual encrypted elements.
///
/// # Errors
///
/// Returns validation or TLV encoding errors from
/// [`validate_bound_profile_package`] and [`Tlv::to_bytes`].
///
/// # Examples
///
/// ```
/// let bpp = euicc::bertlv::Tlv::constructed(
///     euicc::bertlv::Class::ContextSpecific.constructed(54),
///     vec![
///         euicc::bertlv::Tlv::constructed(
///             euicc::bertlv::Class::ContextSpecific.constructed(35),
///             Vec::new(),
///         )?,
///         euicc::bertlv::Tlv::constructed(
///             euicc::bertlv::Class::ContextSpecific.constructed(0),
///             Vec::new(),
///         )?,
///         euicc::bertlv::Tlv::constructed(
///             euicc::bertlv::Class::ContextSpecific.constructed(1),
///             Vec::new(),
///         )?,
///         euicc::bertlv::Tlv::constructed(
///             euicc::bertlv::Class::ContextSpecific.constructed(3),
///             Vec::new(),
///         )?,
///     ],
/// )?;
/// assert_eq!(euicc::bpp::segment_bound_profile_package(&bpp)?.len(), 4);
/// # Ok::<(), euicc::EuiccError>(())
/// ```
pub fn segment_bound_profile_package(bpp: &Tlv) -> Result<Vec<Vec<u8>>> {
    validate_bound_profile_package(bpp)?;

    let initialise_secure_channel = required_child(bpp, 35, "initialiseSecureChannelRequest")?;
    let first_sequence_87 = required_child(bpp, 0, "firstSequenceOf87")?;
    let sequence_88 = required_child(bpp, 1, "sequenceOf88")?;
    let second_sequence_87 = child(bpp, 2);
    let sequence_86 = required_child(bpp, 3, "sequenceOf86")?;

    let mut segments = Vec::new();
    let mut first = bpp.header_bytes()?;
    first.extend_from_slice(&initialise_secure_channel.to_bytes()?);
    segments.push(first);

    segments.push(first_sequence_87.to_bytes()?);
    segments.push(sequence_88.header_bytes()?);
    for item in sequence_88.children().unwrap_or_default() {
        segments.push(item.to_bytes()?);
    }
    if let Some(sequence) = second_sequence_87 {
        segments.push(sequence.to_bytes()?);
    }
    segments.push(sequence_86.header_bytes()?);
    for item in sequence_86.children().unwrap_or_default() {
        segments.push(item.to_bytes()?);
    }

    Ok(segments)
}

fn child(parent: &Tlv, value: u64) -> Option<&Tlv> {
    parent.first(&Class::ContextSpecific.constructed(value))
}

fn required_child<'a>(parent: &'a Tlv, value: u64, name: &'static str) -> Result<&'a Tlv> {
    child(parent, value).ok_or(EuiccError::MissingField(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bertlv::{Class, Tlv};

    #[test]
    fn segment_bound_profile_package_emits_sgp22_transfer_order() {
        // Arrange
        let initialise = Tlv::constructed(
            Class::ContextSpecific.constructed(35),
            vec![
                Tlv::primitive(Class::ContextSpecific.primitive(0), [0x01])
                    .expect("initialise child builds"),
            ],
        )
        .expect("initialise builds");
        let sequence_87 = Tlv::constructed(
            Class::ContextSpecific.constructed(0),
            vec![
                Tlv::primitive(Class::ContextSpecific.primitive(7), [0x87])
                    .expect("87 item builds"),
            ],
        )
        .expect("87 sequence builds");
        let sequence_88 = Tlv::constructed(
            Class::ContextSpecific.constructed(1),
            vec![
                Tlv::primitive(Class::ContextSpecific.primitive(8), [0x88])
                    .expect("88 item builds"),
            ],
        )
        .expect("88 sequence builds");
        let sequence_86 = Tlv::constructed(
            Class::ContextSpecific.constructed(3),
            vec![
                Tlv::primitive(Class::ContextSpecific.primitive(6), [0x86])
                    .expect("86 item builds"),
            ],
        )
        .expect("86 sequence builds");
        let bpp = Tlv::constructed(
            Class::ContextSpecific.constructed(54),
            vec![initialise, sequence_87, sequence_88, sequence_86],
        )
        .expect("BPP builds");

        // Act
        let segments = segment_bound_profile_package(&bpp).expect("BPP segments");

        // Assert
        assert_eq!(segments.len(), 6);
        assert_eq!(
            segments[0],
            vec![0xBF, 0x36, 0x15, 0xBF, 0x23, 0x03, 0x80, 0x01, 0x01]
        );
        assert_eq!(segments[1], vec![0xA0, 0x03, 0x87, 0x01, 0x87]);
        assert_eq!(segments[2], vec![0xA1, 0x03]);
        assert_eq!(segments[3], vec![0x88, 0x01, 0x88]);
        assert_eq!(segments[4], vec![0xA3, 0x03]);
        assert_eq!(segments[5], vec![0x86, 0x01, 0x86]);
    }

    #[test]
    fn validate_rejects_missing_required_branch() {
        // Arrange
        let bpp = Tlv::constructed(Class::ContextSpecific.constructed(54), Vec::new())
            .expect("BPP builds");

        // Act
        let err = validate_bound_profile_package(&bpp);

        // Assert
        assert!(matches!(
            err,
            Err(EuiccError::MissingField("initialiseSecureChannelRequest"))
        ));
    }
}
