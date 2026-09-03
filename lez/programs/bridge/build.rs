fn main() -> Result<(), Box<dyn std::error::Error>> {
    build_utils::include_image_id("lez/programs", "authenticated_transfer")?;
    Ok(())
}
