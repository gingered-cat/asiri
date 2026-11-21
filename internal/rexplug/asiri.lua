-- asiri for Rex: answer secret requests from the command palette.
--
-- `asiri rex install` writes this file and loads it from Rex's init.lua:
--
--   dofile("/path/to/plugins/asiri/init.lua").setup({ bin = "/path/to/asiri", profile = "owner" })
--
-- Answering runs `asiri approve` or `asiri deny` on this machine with your
-- owner profile, so the agent that asked never approves its own request.
-- Rex shows the question on every connected app; the first answer wins.

local M = {}

local CHOICES = {
  { id = "once", title = "Allow once", icon = "star" },
  { id = "15m", title = "Allow for 15 minutes", icon = "clock" },
  { id = "1h", title = "Allow for 1 hour", icon = "clock" },
  { id = "deny", title = "Deny", icon = "gear" },
}

function M.setup(opts)
  opts = opts or {}
  local bin = opts.bin or "asiri"
  local env = { ASIRI_PROFILE = opts.profile or "owner" }

  -- Runs asiri; returns its stdout, or nil and what went wrong.
  local function asiri(args)
    local argv = { bin }
    for _, a in ipairs(args) do argv[#argv + 1] = a end
    local r, err = rex.exec(argv, { env = env, timeout = 20 })
    if r == nil then return nil, err end
    if not r.ok then
      local msg = r.stderr ~= "" and r.stderr or r.stdout
      return nil, (msg:gsub("%s+$", ""))
    end
    return r.stdout
  end

  local function record(id, choice)
    if choice == "deny" then return asiri({ "deny", id }) end
    return asiri({ "approve", id, "--for", choice })
  end

  -- Asks about one request and records the answer. The returned table is
  -- what `rex do asiri_approve` prints for the asiri CLI that is waiting.
  local function ask(id, title, detail)
    local items = {}
    for i, c in ipairs(CHOICES) do
      items[i] = { id = c.id, title = c.title, subtitle = detail, icon = c.icon }
    end
    local choice, why = rex.ui.pick({ title = title or ("asiri request " .. id), items = items, timeout = 120 })
    if choice == nil then
      if why ~= "cancelled" then
        -- timeout, no_client, busy, unsupported, failed: let asiri ask another way
        return { result = "unavailable", reason = why }
      end
      choice = "deny" -- closing the prompt is a no
    end
    local _, err = record(id, choice)
    if err ~= nil then
      rex.log("warn", "asiri: " .. tostring(err))
      return { result = "error", reason = err }
    end
    return { result = choice }
  end

  local function waiting()
    local out, err = asiri({ "pending", "--json" })
    if out == nil then
      rex.log("warn", "asiri: " .. tostring(err))
      return { result = "error", reason = err }
    end
    local ok, list = pcall(rex.json.decode, out)
    if not ok or type(list) ~= "table" or #list == 0 then
      rex.ui.pick({ title = "asiri: nothing is waiting for approval", items = { { id = "ok", title = "OK" } }, timeout = 30 })
      return { result = "none", reason = "empty" }
    end
    local chosen = list[1]
    if #list > 1 then
      local items = {}
      for i, r in ipairs(list) do
        items[i] = { id = r.id, title = r.title, subtitle = r.detail, icon = "person" }
      end
      local id = rex.ui.pick({ title = "asiri: requests waiting for approval", items = items, timeout = 120 })
      if id == nil then return { result = "none" } end
      for _, r in ipairs(list) do
        if r.id == id then chosen = r end
      end
    end
    return ask(chosen.id, chosen.title, chosen.detail)
  end

  rex.action({
    name = "asiri_approve",
    title = "Asiri: Approve Waiting Requests…",
    description = "Answer a request from an agent to use a secret",
    category = "Asiri",
    keywords = "secret approve deny grant",
    args = { id = "string?", title = "string?", detail = "string?" },
    run = function(ctx, args)
      if args.id == nil then return waiting() end
      return ask(args.id, args.title, args.detail)
    end,
  })

  rex.action({
    name = "asiri_revoke_all",
    title = "Asiri: Revoke Everything (Kill Switch)",
    description = "Revoke every grant and deny every waiting request",
    category = "Asiri",
    run = function()
      local c = rex.ui.pick({
        title = "Revoke every grant and deny waiting requests?",
        items = { { id = "yes", title = "Revoke everything", icon = "gear" }, { id = "no", title = "Cancel" } },
        timeout = 60,
      })
      if c ~= "yes" then return { result = "cancelled" } end
      local out, err = asiri({ "revoke", "--all" })
      if out == nil then error(tostring(err), 0) end
      return { result = (out:gsub("%s+$", "")) }
    end,
  })

  rex.action({
    name = "asiri_lock",
    title = "Asiri: Lock the Vault",
    category = "Asiri",
    run = function()
      local out, err = asiri({ "lock" })
      if out == nil then error(tostring(err), 0) end
      return { result = "locked" }
    end,
  })
end

return M
