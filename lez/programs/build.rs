fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "artifacts")]
    build_utils::include_artifacts("lez/programs")?;

    Ok(())
}
