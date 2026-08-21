args <- commandArgs(trailingOnly = TRUE)
if (length(args) != 2L) {
  stop("usage: run-render.R <submission-dir> <output-dir>", call. = FALSE)
}

submission_dir <- normalizePath(args[[1]], mustWork = TRUE)
output_dir <- normalizePath(args[[2]], mustWork = TRUE)
render_script <- file.path(submission_dir, "payload", "code", "render.R")
input_dir <- file.path(submission_dir, "payload", "data")
output_png <- file.path(output_dir, "preview.png")

if (!file.exists(render_script) || file.info(render_script)$isdir) {
  stop("fixed render entrypoint is missing", call. = FALSE)
}
if (!dir.exists(input_dir)) {
  stop("fixed synthetic-data directory is missing", call. = FALSE)
}
if (file.exists(output_png)) {
  stop("render output must not pre-exist", call. = FALSE)
}

status <- system2(
  file.path(R.home("bin"), "Rscript"),
  c(
    "--vanilla",
    render_script,
    "--input-dir", input_dir,
    "--output", output_png
  ),
  stdout = file.path(output_dir, "render.stdout.txt"),
  stderr = file.path(output_dir, "render.stderr.txt"),
  wait = TRUE,
  timeout = 150
)
if (!identical(status, 0L)) {
  stop(sprintf("render entrypoint failed with status %s", status), call. = FALSE)
}
if (!file.exists(output_png) || file.info(output_png)$size <= 0) {
  stop("render entrypoint did not create a PNG", call. = FALSE)
}

signature <- readBin(output_png, what = "raw", n = 8L)
expected <- as.raw(c(137, 80, 78, 71, 13, 10, 26, 10))
if (!identical(signature, expected)) {
  stop("render output is not a PNG", call. = FALSE)
}

writeLines(
  c(
    paste0("R=", R.version.string),
    paste0("platform=", R.version$platform),
    paste0("outputBytes=", file.info(output_png)$size)
  ),
  file.path(output_dir, "runtime.txt"),
  useBytes = TRUE
)
