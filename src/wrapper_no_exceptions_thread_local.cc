#include "wrapper_no_exceptions.h"

#include <thread>

#include "wrapper.hpp"

namespace challenge_bypass_ristretto {

thread_local TokenException token_exception = TokenException::none();

TokenException* GetOrCreateLastException() {
  return &token_exception;
}

const TokenException& TokenException::none() {
  static const TokenException token_exception_none("");
  return token_exception_none;
}

}
