(module
  (import "math" "add_bias" (func $add_bias (param i32) (result i32)))
  (func (export "run") (param $raw_score i32) (result i32)
    local.get $raw_score
    call $add_bias)
)
