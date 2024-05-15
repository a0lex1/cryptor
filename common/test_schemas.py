test_schema_1 = {
  "type": "object",
  "properties": {

    "somelistA": {"type": "array", "items": {"type": "number"}},
    "somelistB": {"type": "array", "items": {"type": "number"}},
    "someintA": {"type": "number"},
    "someintB": {"type": "number"},
    "someboolA": {"type": "boolean"},
    "someboolB": {"type": "boolean"},
    "someboolC": {"type": "boolean"},

    "sub": {
      "type": "object",
      "properties": {
        "sex": {"type": "string"},
        "age": {"type": "number"},

        "super": {"type": "number"},
        "mega": {"type": "number"}
      }
    }
  }
}

test_schema_2 = {
  "type": "object",
  "properties": {
    "hex": {
      "type": "object",
      "properties": {
        "fuck1": {"type": "boolean"},
        "fuck2": {"type": "boolean"}
      }
    }
  }
}

test_schema_3 = {
  "type": "object",
  "properties": {
    "name": {"type": "string", "default": "John"},
    "address": {"type": "string", "default": "Dave"},
    "details": {
      "type": "object",
      "properties": {
        "sex": {"type": "string", "enum": ["male", "female", "trans"], "default": "trans"},
        "age": {"type": "number", "default": 21},
        "alias": { "type": "string" } # no default
      }
    }
  }
}

