#pragma once

namespace jay::ip {
enum class IPHeaderError {
  OUT_OF_BOUNDS,
  NOT_ALIGNED,
  BAD_VERSION,
  CHECKSUM_ERROR,
  CANNOT_COPY_OPTION,
  NO_SIZE_HINT
};

enum class ICMPHeaderError { 
  OUT_OF_BOUNDS, 
  INVALID_CODE,
  NO_SIZE_HINT 
};
}
