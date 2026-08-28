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

log_file <- tempfile("sfl-render-", fileext = ".log")
status <- system2(
  file.path(R.home("bin"), "Rscript"),
  c(
    "--vanilla",
    render_script,
    "--input-dir", input_dir,
    "--output", output_png
  ),
  stdout = log_file,
  stderr = log_file,
  wait = TRUE,
  timeout = 150
)
if (!identical(status, 0L)) {
  details <- tryCatch(paste(readLines(log_file, warn = FALSE), collapse = "\n"), error = function(e) "")
  if (nzchar(details)) message(details)
  stop(sprintf("render entrypoint failed with status %s", status), call. = FALSE)
}
if (!file.exists(output_png) || file.info(output_png)$size <= 0) {
  stop("render entrypoint did not create a PNG", call. = FALSE)
}
if (file.info(output_png)$size > 64 * 1024 * 1024) {
  stop("render output exceeds 64 MiB", call. = FALSE)
}

signature <- readBin(output_png, what = "raw", n = 8L)
expected <- as.raw(c(137, 80, 78, 71, 13, 10, 26, 10))
if (!identical(signature, expected)) {
  stop("render output is not a PNG", call. = FALSE)
}

input <- file(output_png, open = "rb")
output <- file("/dev/stdout", open = "wb")
on.exit(close(input), add = TRUE)
on.exit(close(output), add = TRUE)
repeat {
  block <- readBin(input, what = "raw", n = 1024L * 1024L)
  if (!length(block)) break
  writeBin(block, output, useBytes = TRUE)
}
flush(output)
message(paste0("R=", R.version.string, "; platform=", R.version$platform, "; outputBytes=", file.info(output_png)$size))
