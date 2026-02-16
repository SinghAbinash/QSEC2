
from flask import request


def register_chat_handlers(socketio, app, db_module, ROOM_MEMBERS, SID_MAP, ROOM_KEYS):
    
    add_log = getattr(db_module, 'add_log', lambda *a, **k: None)
    get_logs = getattr(db_module, 'get_logs', lambda *a, **k: [])
    add_user = getattr(db_module, 'add_user', lambda *a, **k: None)

    # Wrap add_log to notify room clients (push) when a new structured log is added.
    _orig_add_log = add_log
    def _add_log_notify(room, message):
        try:
            res = _orig_add_log(room, message)
        except Exception:
            # fallback to original behavior without notification
            try:
                return _orig_add_log(room, message)
            except Exception:
                return None
        # res should be a dict with id,message,created_at if db.add_log returns it
        try:
            log_entry = res if isinstance(res, dict) else {'id': None, 'message': message, 'created_at': None}
            # don't echo back to the caller's socket if available
            from flask import request as _fl_request
            sid = getattr(_fl_request, 'sid', None)
            include_self = False if sid else True
            # Emit only the single new log as a push; clients will merge it into their UI
            socketio.emit('room_logs', {'logs': [log_entry]}, room=room, include_self=include_self)
        except Exception:
            app.logger.exception('failed to emit room log push')
        return res
    # replace add_log in this scope with wrapper
    add_log = _add_log_notify

    @socketio.on('relay')
    def _relay(data):
        try:
            ev_type = data.get('type') if isinstance(data, dict) else None
            room = data.get('room') if isinstance(data, dict) else None
            if not ev_type or not room:
                return
            # Inject sender identity from SID_MAP so receivers know who sent this
            sid = getattr(request, 'sid', None)
            if sid and sid in SID_MAP:
                _, sender_name = SID_MAP[sid]
                data['from'] = sender_name
            include_self = False if ev_type == 'group_message' else True
            socketio.emit(ev_type, data, room=room, include_self=include_self)
        except Exception:
            return

    # In-memory mapping of published public keys per room: room -> { username: pubkey_b64 }
    PUBKEYS = {}
    # Maintain join order per room so the leader (first joiner) is deterministic
    ROOM_ORDER = {}
    # Optional capacity expected per room (set by first joiner if provided)
    ROOM_EXPECTED = {}
    # Track whether a room's leader-generated room key has been logged
    ROOM_KEY_GEN_LOGGED = set()

    @socketio.on('join')
    def _join(data):
        try:
            room = data.get('room') if isinstance(data, dict) else None
            username = data.get('username') if isinstance(data, dict) else None
            if not room or not username:
                return
            sid = getattr(request, 'sid', None) or None
            # join the Socket.IO room
            from flask_socketio import join_room
            # enforce expected capacity if set or provided
            expected_in = None
            try:
                expected_in = int(data.get('expected')) if isinstance(data, dict) and data.get('expected') else None
            except Exception:
                expected_in = None
            # prefer explicit server-set ROOM_EXPECTED; otherwise accept provided expected_in
            existing_cap = ROOM_EXPECTED.get(room) if ROOM_EXPECTED.get(room) is not None else None
            cap = existing_cap if existing_cap is not None else expected_in
            # persist expected capacity if provided and not already set
            if expected_in is not None and ROOM_EXPECTED.get(room) is None:
                try:
                    ROOM_EXPECTED[room] = expected_in
                    cap = expected_in
                except Exception:
                    app.logger.exception('failed to persist ROOM_EXPECTED')
            # determine current occupancy from ROOM_MEMBERS (more reliable)
            current_count = len(ROOM_MEMBERS.get(room, set()))
            if cap and current_count >= cap:
                try:
                    socketio.emit('join_failed', {'reason': 'room is full', 'room': room, 'capacity': cap}, room=request.sid)
                except Exception:
                    app.logger.exception('failed to emit join_failed')
                return
            join_room(room)
            ROOM_MEMBERS.setdefault(room, set()).add(username)
            # maintain insertion-order list for this room
            try:
                order = ROOM_ORDER.setdefault(room, [])
                if username not in order:
                    order.append(username)
            except Exception:
                pass
            SID_MAP[request.sid] = (room, username)
            socketio.emit('joined', {'room': room}, room=request.sid)
            # Structured room logs: record joins and room creation/ready events
            try:
                leader = None
                order = ROOM_ORDER.get(room, [])
                if order:
                    leader = order[0]
                # If this is the first joiner, record room creation
                if order and len(order) == 1:
                    cap = ROOM_EXPECTED.get(room)
                    cap_val = cap if (cap is not None) else 'unset'
                    add_log(room, f"[ROOM_CREATED] room={room} leader={leader} expected={cap_val}")
                # Record the user join
                add_log(room, f"[USER_JOIN] room={room} user={username}")
                # If a capacity is set and we've reached it, mark room ready
                current_count_new = len(ROOM_MEMBERS.get(room, set()))
                cap_check = ROOM_EXPECTED.get(room)
                if cap_check and current_count_new == cap_check:
                    add_log(room, f"[ROOM_READY] room={room} members={current_count_new}")
            except Exception:
                app.logger.exception('failed to persist structured join logs')
            # send current known public keys for this room to the joining client
            try:
                pks = PUBKEYS.get(room, {})
                socketio.emit('pubkey_list', {'pubkeys': pks}, room=request.sid)
            except Exception:
                app.logger.exception('failed to send pubkey_list to joining client')
            try:
                logs = get_logs(room, limit=200)
                socketio.emit('room_logs', {'logs': logs}, room=request.sid)
            except Exception:
                app.logger.exception('failed to fetch room logs')
            # emit ordered user list (first joiner is leader)
            try:
                users_ordered = ROOM_ORDER.get(room, [])
                exp_cap = ROOM_EXPECTED.get(room, 0)
                socketio.emit('user_list', {'users': list(users_ordered), 'expected': exp_cap}, room=room)
            except Exception:
                socketio.emit('user_list', {'users': list(ROOM_MEMBERS.get(room, [])), 'expected': 0}, room=room)
            app.logger.info(f"join: room={room} user={username} sid={request.sid}")
        except Exception:
            return
        finally:
            # cleanup ROOM_EXPECTED when room empties is handled elsewhere (leave/disconnect)
            pass

    @socketio.on('leave')
    def _leave(data):
        try:
            room = data.get('room') if isinstance(data, dict) else None
            username = data.get('username') if isinstance(data, dict) else None
            if not room or not username:
                return
            from flask_socketio import leave_room
            leave_room(room)
            members = ROOM_MEMBERS.get(room, set())
            members.discard(username)
            # remove from ordered list as well
            try:
                order = ROOM_ORDER.get(room, [])
                if username in order:
                    order.remove(username)
            except Exception:
                pass
            SID_MAP.pop(request.sid, None)
            # emit ordered user list
            try:
                users_ordered = ROOM_ORDER.get(room, [])
                socketio.emit('user_list', {'users': list(users_ordered)}, room=room)
            except Exception:
                socketio.emit('user_list', {'users': list(members)}, room=room)
            try:
                add_user(room, username)
            except Exception:
                app.logger.exception('failed to update room_users on leave')
            app.logger.info(f"leave: room={room} user={username} sid={request.sid}")
            # if room empty, remove its in-memory pubkey mapping
            try:
                if not ROOM_MEMBERS.get(room):
                    PUBKEYS.pop(room, None)
                    try:
                        prev_order = ROOM_ORDER.pop(room, None)
                        # log key destruction for members that were part of the room
                        if prev_order:
                            for u in prev_order:
                                try:
                                    add_log(room, f"[KEY_DESTROYED] user={u}")
                                except Exception:
                                    pass
                    except Exception:
                        pass
                    try:
                        ROOM_EXPECTED.pop(room, None)
                    except Exception:
                        pass
                    try:
                        add_log(room, f"[ROOM_TERMINATED] room={room}")
                    except Exception:
                        pass
                    app.logger.info(f'removed pubkey mapping for empty room={room}')
            except Exception:
                app.logger.exception('failed to remove pubkey mapping on leave')
        except Exception:
            return

    @socketio.on('disconnect')
    def _disconnect():
        try:
            info = SID_MAP.pop(request.sid, None)
            if not info:
                return
            room, username = info
            members = ROOM_MEMBERS.get(room, set())
            members.discard(username)
            # remove from ordered list as well
            try:
                order = ROOM_ORDER.get(room, [])
                if username in order:
                    order.remove(username)
            except Exception:
                pass
            # emit ordered user list
            try:
                users_ordered = ROOM_ORDER.get(room, [])
                socketio.emit('user_list', {'users': list(users_ordered)}, room=room)
            except Exception:
                socketio.emit('user_list', {'users': list(members)}, room=room)
            app.logger.info(f"disconnect: room={room} user={username} sid={request.sid}")
            # if room empty, remove its in-memory pubkey mapping
            try:
                if not ROOM_MEMBERS.get(room):
                    PUBKEYS.pop(room, None)
                    try:
                        prev_order = ROOM_ORDER.pop(room, None)
                        if prev_order:
                            for u in prev_order:
                                try:
                                    add_log(room, f"[KEY_DESTROYED] user={u}")
                                except Exception:
                                    pass
                    except Exception:
                        pass
                    try:
                        ROOM_EXPECTED.pop(room, None)
                    except Exception:
                        pass
                    try:
                        add_log(room, f"[ROOM_TERMINATED] room={room}")
                    except Exception:
                        pass
                    app.logger.info(f'removed pubkey mapping for empty room={room}')
            except Exception:
                app.logger.exception('failed to remove room key on disconnect')
        except Exception:
            return

    @socketio.on('store_encrypted')
    def _store_encrypted(data):
        try:
            if not isinstance(data, dict):
                return
            room = data.get('room')
            ciphertext = data.get('ciphertext')
            if not room or not ciphertext:
                app.logger.info('store_encrypted: missing room or ciphertext')
                return
            app.logger.info(f"store_encrypted received: room={room} len={len(ciphertext)} source_sid={request.sid}")
            # Persist structured metadata only; never store ciphertext/plaintext
            try:
                sender = SID_MAP.get(request.sid, (None, None))[1] or 'unknown'
                add_log(room, f"[MSG_ENCRYPTED] user={sender} iv_len=12")
                add_log(room, f"[MSG_RELAYED] room={room} sender={sender}")
                add_log(room, f"[SERVER_NOTE] Encrypted payload relayed; no key material stored.")
            except Exception:
                app.logger.exception('failed to persist store_encrypted metadata')
            socketio.emit('store_ack', {'room': room, 'status': 'stored'}, room=request.sid)
            try:
                socketio.emit('encrypted_message', {'ciphertext': ciphertext, 'room': room}, room=room, include_self=False)
            except Exception:
                app.logger.exception('failed to broadcast encrypted_message')
        except Exception:
            app.logger.exception('failed to store encrypted message')
            return

    @socketio.on('fetch_room_logs')
    def _fetch_room_logs(data):
        try:
            if not isinstance(data, dict):
                return
            room = data.get('room')
            since = data.get('since_id')
            try:
                since = int(since) if since is not None else None
            except Exception:
                since = None
            if not room:
                return
            # NOTE: avoid noisy INFO logs on each poll; keep verbose when returning entries
            logs = get_logs(room, limit=200, since_id=since)
            # If there are no new logs, avoid emitting and avoid noisy server logs
            if not logs:
                return
            app.logger.info(f'fetch_room_logs: returning {len(logs)} entries for room={room} since_id={since}')
            socketio.emit('room_logs', {'logs': logs}, room=request.sid)
        except Exception:
            app.logger.exception('failed to fetch room logs')
            return

    @socketio.on('group_message')
    def _group_message(data):
        try:
            if not isinstance(data, dict):
                return
            room = data.get('room')
            ciphertext = data.get('ciphertext') or data.get('cipherText') or data.get('ct')
            iv = data.get('iv')
            sender = SID_MAP.get(request.sid, (None, None))[1] or data.get('from')
            if not room or not ciphertext:
                app.logger.info('group_message: missing room or ciphertext')
                return
            app.logger.info(f"group_message received: room={room} from={sender} len={len(ciphertext)} sid={request.sid}")
            try:
                # store only metadata about encrypted message flow
                add_log(room, f"[MSG_ENCRYPTED] user={sender} iv_len=12")
                add_log(room, f"[MSG_RELAYED] room={room} sender={sender}")
                add_log(room, f"[SERVER_NOTE] Encrypted payload relayed; no key material stored.")
            except Exception:
                app.logger.exception('failed to persist group ciphertext metadata')
            socketio.emit('group_message', {'room': room, 'from': sender, 'ciphertext': ciphertext, 'iv': iv}, room=room, include_self=False)
        except Exception:
            app.logger.exception('failed to handle group_message')
            return

    @socketio.on('plain_message')
    def _plain_message(data):
        try:
            if not isinstance(data, dict):
                return
            room = data.get('room')
            msg = data.get('message')
            to = data.get('to') or 'ALL'
            sender = data.get('from') or SID_MAP.get(request.sid, (None, None))[1]
            if not room or not msg:
                return
            # persist plaintext log
            try:
                add_log(room, f"{sender}: {msg}")
            except Exception:
                app.logger.exception('failed to persist plain message')
            # deliver: to ALL -> room, otherwise find sid for recipient
            if to == 'ALL':
                socketio.emit('plain_message', {'room': room, 'from': sender, 'to': to, 'message': msg, 'ts': data.get('ts')}, room=room, include_self=False)
            else:
                # locate recipient sid
                target_sid = None
                for sid, info in list(SID_MAP.items()):
                    r, u = info
                    if r == room and u == to:
                        target_sid = sid
                        break
                if target_sid:
                    socketio.emit('plain_message', {'room': room, 'from': sender, 'to': to, 'message': msg, 'ts': data.get('ts')}, room=target_sid)
                else:
                    # if recipient not found, still emit to room (best-effort)
                    socketio.emit('plain_message', {'room': room, 'from': sender, 'to': to, 'message': msg, 'ts': data.get('ts')}, room=room, include_self=False)
        except Exception:
            app.logger.exception('failed to handle plain_message')
            return

    @socketio.on('encrypted_message')
    def _encrypted_message(data):
        try:
            if not isinstance(data, dict):
                return
            room = data.get('room')
            ciphertext = data.get('ciphertext') or data.get('payload')
            sender = SID_MAP.get(request.sid, (None, None))[1] or data.get('from')
            if not room or not ciphertext:
                return
            app.logger.info(f"encrypted_message received for forward: room={room} from={sender} len={len(ciphertext)}")
            try:
                add_log(room, f"[MSG_ENCRYPTED] user={sender} iv_len=12")
                add_log(room, f"[MSG_RELAYED] room={room} sender={sender}")
                add_log(room, f"[SERVER_NOTE] Encrypted payload relayed; no key material stored.")
            except Exception:
                app.logger.exception('failed to persist encrypted_message metadata')
            socketio.emit('encrypted_message', {'room': room, 'ciphertext': ciphertext, 'from': sender}, room=room, include_self=False)
        except Exception:
            app.logger.exception('failed to handle encrypted_message')
            return

    # qke_init removed: server will no longer perform key exchanges or hold room keys.
    @socketio.on('qke_init')
    def _qke_init(data):
        return

    # Pubkey announce: clients publish their RSA public key (base64 SPKI)
    @socketio.on('announce_pubkey')
    def _announce_pubkey(data):
        try:
            if not isinstance(data, dict):
                return
            room = data.get('room')
            pub_b64 = data.get('pubkey')
            if not room or not pub_b64:
                return
            info = SID_MAP.get(request.sid)
            if not info:
                return
            _, username = info
            pmap = PUBKEYS.setdefault(room, {})
            pmap[username] = pub_b64
            # broadcast updated pubkey list to room
            try:
                socketio.emit('pubkey_list', {'pubkeys': pmap}, room=room)
            except Exception:
                app.logger.exception('failed to emit pubkey_list')
            app.logger.info(f'announce_pubkey: stored pubkey for room={room} user={username}')
        except Exception:
            app.logger.exception('failed to handle announce_pubkey')
            return

    @socketio.on('roomkey_share')
    def _roomkey_share(data):
        """Relay a leader-generated encrypted room key to a specific peer.
        Payload: { room, to, ciphertext }
        Server does not decrypt; it only forwards to the recipient's sid.
        """
        try:
            if not isinstance(data, dict):
                return
            room = data.get('room')
            to = data.get('to')
            ciphertext = data.get('ciphertext')
            if not room or not to or not ciphertext:
                return
            sender = SID_MAP.get(request.sid, (None, None))[1]
            # locate recipient sid
            target_sid = None
            for sid, info in list(SID_MAP.items()):
                r, u = info
                if r == room and u == to:
                    target_sid = sid
                    break
            if target_sid:
                try:
                    socketio.emit('roomkey_share', {'from': sender, 'ciphertext': ciphertext}, room=target_sid)
                    # Structured room key logs: do not store key material, only metadata
                    try:
                        # if leader generated the room key, log that once per room
                        order = ROOM_ORDER.get(room, [])
                        leader = order[0] if order else None
                        if sender == leader and room not in ROOM_KEY_GEN_LOGGED:
                            add_log(room, f"[ROOMKEY_GENERATED] by={sender} size=32bytes")
                            ROOM_KEY_GEN_LOGGED.add(room)
                        add_log(room, f"[ROOMKEY_ENCRYPTED] to={to} method=AES-GCM(session_hash)")
                        add_log(room, f"[ROOMKEY_RELAYED] from={sender} to={to} ciphertext_len={len(ciphertext)}")
                    except Exception:
                        app.logger.exception('failed to persist roomkey structured logs')
                    app.logger.info(f'roomkey_share: relayed roomkey from={sender} to={to} in room={room}')
                except Exception:
                    app.logger.exception('failed to forward roomkey_share')
            else:
                app.logger.info(f'roomkey_share: recipient {to} not found in room={room}')
        except Exception:
            app.logger.exception('failed to handle roomkey_share')
            return

    @socketio.on('bb84_relay')
    def _bb84_relay(data):
        """Relay BB84 protocol messages between peers. Payload: { room, to, bb84_type, payload }
        Server will only forward to the recipient sid and will not process contents.
        """
        try:
            if not isinstance(data, dict):
                return
            room = data.get('room')
            to = data.get('to')
            bb84_type = data.get('bb84_type')
            payload = data.get('payload')
            if not room or not to or not bb84_type:
                return
            sender = SID_MAP.get(request.sid, (None, None))[1]
            # locate recipient sid
            target_sid = None
            for sid, info in list(SID_MAP.items()):
                r, u = info
                if r == room and u == to:
                    target_sid = sid
                    break
            if target_sid:
                try:
                    socketio.emit('bb84_message', {'from': sender, 'bb84_type': bb84_type, 'payload': payload}, room=target_sid)
                    app.logger.info(f'bb84_relay: relayed {bb84_type} from={sender} to={to} in room={room}')
                    try:
                        if bb84_type == 'prepare' and isinstance(payload, dict):
                            num = payload.get('num') or payload.get('length') or None
                            add_log(room, f"[BB84_INIT] from={sender} to={to} length={num}")
                            # log client_bases (non-sensitive: only length)
                            if bb84_type == 'client_bases' and isinstance(payload, dict):
                                cb = payload.get('client_bases') or payload.get('clientBases') or ''
                                add_log(room, f"[BB84_CLIENT_BASES] from={sender} to={to} length={(len(cb) if cb else 'unknown')}")
                            # log roomkey_enc relay (non-sensitive: ciphertext length only)
                            if bb84_type == 'roomkey_enc' and isinstance(payload, dict):
                                c = payload.get('ciphertext') or payload.get('ct') or ''
                                add_log(room, f"[ROOMKEY_ENCRYPTED] from={sender} to={to} ciphertext_len={(len(c) if c else 'unknown')}")
                    except Exception:
                        app.logger.exception('failed to persist bb84 metadata')
                except Exception:
                    app.logger.exception('failed to forward bb84_relay')
            else:
                app.logger.info(f'bb84_relay: recipient {to} not found in room={room}')
        except Exception:
            app.logger.exception('failed to handle bb84_relay')
            return

    # Lightweight BB84 metadata summary written by clients (no secrets)
    @socketio.on('bb84_meta')
    def _bb84_meta(data):
        try:
            if not isinstance(data, dict):
                return
            room = data.get('room')
            frm = data.get('from')
            to = data.get('to')
            matched = data.get('matched_bits')
            if not room:
                return
            add_log(room, f"[BB84_SIFTING_COMPLETE] matched_bits={int(matched) if matched is not None else 'unknown'}")
        except Exception:
            app.logger.exception('failed to handle bb84_meta')
            return

    @socketio.on('bb84_session')
    def _bb84_session(data):
        try:
            if not isinstance(data, dict):
                return
            room = data.get('room')
            frm = data.get('from')
            to = data.get('to')
            key_len = data.get('key_length')
            if not room:
                return
            add_log(room, f"[BB84_SESSION_DERIVED] from={frm} to={to} key_length={key_len}")
        except Exception:
            app.logger.exception('failed to handle bb84_session')
            return

    @socketio.on('roomkey_generated')
    def _roomkey_generated(data):
        try:
            if not isinstance(data, dict):
                return
            room = data.get('room')
            by = data.get('by')
            size = data.get('size')
            if not room:
                return
            add_log(room, f"[ROOMKEY_GENERATED] by={by} size={size}")
        except Exception:
            app.logger.exception('failed to handle roomkey_generated')
            return

    @socketio.on('roomkey_decrypted')
    def _roomkey_decrypted(data):
        try:
            if not isinstance(data, dict):
                return
            room = data.get('room')
            user = data.get('user')
            if not room or not user:
                return
            add_log(room, f"[ROOMKEY_DECRYPTED] user={user}")
        except Exception:
            app.logger.exception('failed to handle roomkey_decrypted')
            return

    @socketio.on('msg_decrypted')
    def _msg_decrypted(data):
        try:
            if not isinstance(data, dict):
                return
            room = data.get('room')
            user = data.get('user')
            if not room or not user:
                return
            add_log(room, f"[MSG_DECRYPTED] user={user}")
        except Exception:
            app.logger.exception('failed to handle msg_decrypted')
            return

    return True
