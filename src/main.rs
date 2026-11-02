            Ok(SovereignCommand::StreamDigest(digest))
                if digest.len() <= yukkios::STREAM_REGISTRY_MAX_STREAMS =>
            {
                for descriptor in registry.descriptors_for_digest(&digest)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
                {
                    let announcement = StreamAnnouncement {
                        message_id: Uuid::new_v4().to_string(),
                        remaining_hops: yukkios::STREAM_ANNOUNCEMENT_MAX_HOPS,
                        descriptor,
                    };
                    let bytes = serde_json::to_vec(
                        &SovereignCommand::StreamAnnouncement(announcement),
                    ).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                    send_frame(&mut stream, &mut session, &bytes).await?;
                }
            }
