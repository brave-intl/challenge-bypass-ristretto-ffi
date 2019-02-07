#include "wrapper_no_exceptions.h"

#include "base/no_destructor.h"
#include "base/threading/thread_local.h"
#include "wrapper.hpp"

namespace challenge_bypass_ristretto {

TokenException* GetOrCreateLastException() {
  static base::NoDestructor<base::ThreadLocalPointer<TokenException>>
      last_exception;
  TokenException* token_exception = last_exception.get()->Get();
  if (!token_exception)
    last_exception.get()->Set(new TokenException(""));
  return token_exception;
}

const TokenException& TokenException::none() {
  static base::NoDestructor<TokenException> token_exception_none("");
  return *token_exception_none;
}

}
