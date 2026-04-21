/// Macro for tail-calling another program and requesting a return (CPS).

#[macro_export]
macro_rules! call_program {
    (
        // Current execution context (obtained from read_nssa_inputs)
        ctx: $ctx:expr,
        target: $target_id:expr, 
        func: $target_fn:ident ( $($arg:expr),* ) => then $continue_fn:ident ( $local_state:expr ) 
    ) => {
        {
            use $crate::prelude::risc0_zkvm::serde::to_vec;
            use $crate::prelude::sha2::{Sha256, Digest};
            use $crate::prelude::bytemuck;

            // 1. Serialize Context/Local State Program A
            let state_u32 = to_vec(&$local_state).expect("Failed to serialize state");
            let continuation_id = stringify!($continue_fn).to_string();
            
            // 2. Generate Unforgeable Capability Ticket Hash
            // Hash(SelfID + ContinuationID + StatePayload)
            let mut hasher = Sha256::new();
            hasher.update(bytemuck::cast_slice(&$ctx.self_program_id));
            hasher.update(continuation_id.as_bytes());
            hasher.update(bytemuck::cast_slice(&state_u32)); // Casting sementara!
            let ticket_hash: [u8; 32] = hasher.finalize().into();

            // 3. Build the Return Route to be handed to Program B
            let route = $crate::routing::ReturnRoute {
                caller_program_id: $ctx.self_program_id.clone(),
                continuation_id,
                ticket_hash,
                context_payload: state_u32,
            };

            // 4. Wrap the instruction for Program B
            let args_tuple = ( $($arg),* );
            let args_u32 = to_vec(&args_tuple).unwrap();

            let b_instruction = $crate::routing::GeneralCallInstruction {
                route: Some(route),
                function_id: stringify!($target_fn).to_string(),
                args: args_u32,
            };

            // 5. Create a pure LEZ-native ChainedCall
            let call = nssa_core::program::ChainedCall::new(
                $target_id,
                $ctx.pre_states.clone(), // Pass along state access
                &b_instruction,
            );

            // 6. Write ProgramOutput and stop the VM (Phase 1 complete)
            nssa_core::program::ProgramOutput::new(
                $ctx.self_program_id.clone(),
                $ctx.caller_program_id.clone(),
                $ctx.raw_instruction_data.clone(),
                $ctx.pre_states.clone(),
                vec![] // Post state is empty because execution is being delegated to B
            )
            .with_chained_calls(vec![call])
            .with_issued_tickets(vec![ticket_hash]) // <--- LP-0015 TICKET INJECTION
            .write();

            unsafe { $crate::routing::IS_TAIL_CALL = true; }
            return vec![];
        }
    };
}

/// Macro for Program B to easily return a value to Program A
#[macro_export]
macro_rules! return_to_caller {
    (ctx: $ctx:expr, route: $route:expr, result: $result:expr) => {
        {
            use risc0_zkvm::serde::to_vec;

            // Build the instruction to call Program A's #[internal] function
            let return_instruction = $crate::routing::GeneralCallInstruction {
                route: Some($route.clone()), // Return the ticket intact
                function_id: $route.continuation_id.clone(),
                args: to_vec(&$result).unwrap(),
            };

            let call = nssa_core::program::ChainedCall::new(
                $route.caller_program_id,
                $ctx.pre_states.clone(),
                &return_instruction
            );

            nssa_core::program::ProgramOutput::new(
                $ctx.self_program_id.clone(),
                $ctx.caller_program_id.clone(),
                $ctx.raw_instruction_data.clone(),
                $ctx.pre_states.clone(),
                vec![]
            )
            .with_chained_calls(vec![call])
            .write();

            unsafe { $crate::routing::IS_TAIL_CALL = true; }
            return vec![];
        }
    };
}

#[macro_export]
macro_rules! lez_dispatcher {
    (
        public: [ $( $pub_fn:ident ),* $(,)? ],
        internal: [ $( $int_fn:ident ),* $(,)? ]
    ) => {
        risc0_zkvm::guest::entry!(main);

        fn main() {
            let ctx = $crate::routing::ExecCtx::read();
            
            // Parse the wrapper instruction (GeneralCallInstruction)
            let instruction: $crate::routing::GeneralCallInstruction = 
                risc0_zkvm::serde::from_slice(&ctx.raw_instruction_data)
                .expect("Failed to parse general call instruction");

            match instruction.function_id.as_str() {
                // --- Route for #[public] functions ---
                $(
                    stringify!($pub_fn) => {
                        let args = risc0_zkvm::serde::from_slice(&instruction.args).unwrap();
                        
                        // Execute the public function
                        let post_states = $pub_fn(ctx.clone(), args);
                        
                        // If this public function does not call_program! (ends normally), write output:
                        if unsafe { !$crate::routing::IS_TAIL_CALL } {
                            nssa_core::program::ProgramOutput::new(
                                ctx.self_program_id,
                                ctx.caller_program_id,
                                ctx.raw_instruction_data,
                                ctx.pre_states,
                                post_states
                            ).write();
                        }
                    }
                )*
                
                // --- Route for #[internal] functions ---
                $(
                    stringify!($int_fn) => {
                        // Must have a valid ReturnRoute from the tail-call
                        let route = instruction.route.expect("Access Denied: continuation route missing!");
                        
                        let result = risc0_zkvm::serde::from_slice(&instruction.args).unwrap();
                        let local_state = risc0_zkvm::serde::from_slice(&route.context_payload).unwrap();

                        // Execute the internal function
                        let post_states = $int_fn(ctx.clone(), local_state, result);

                        // Write the final output while CONSUMING THE TICKET (validation happens in the Host Sequencer)
                        if unsafe { !$crate::routing::IS_TAIL_CALL } {
                            nssa_core::program::ProgramOutput::new(
                                ctx.self_program_id,
                                ctx.caller_program_id,
                                ctx.raw_instruction_data,
                                ctx.pre_states,
                                post_states
                            )
                            .with_consumed_ticket(route.ticket_hash)
                            .write();
                        }
                    }
                )*
                _ => panic!("Function {} not found in dispatcher!", instruction.function_id),
            }
        }
    };
}