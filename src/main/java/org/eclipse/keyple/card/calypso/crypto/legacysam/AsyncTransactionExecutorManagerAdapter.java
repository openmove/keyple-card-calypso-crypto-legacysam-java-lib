/* **************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.eclipse.keyple.card.calypso.crypto.legacysam;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import java.util.ArrayList;
import java.util.List;
import org.eclipse.keyple.core.util.json.JsonUtil;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.AsyncTransactionExecutorManager;
import org.eclipse.keypop.card.ProxyReaderApi;

/**
 * Adapter of {@link AsyncTransactionExecutorManager}.
 *
 * @since 0.3.0
 */
final class AsyncTransactionExecutorManagerAdapter extends CommonTransactionManagerAdapter
    implements AsyncTransactionExecutorManager {

  /**
   * Constructs a new instance with the specified target SAM reader, target SAM and commands to be
   * executed.
   *
   * @param targetSamReader The reader through which the target SAM communicates.
   * @param targetSam The target legacy SAM.
   * @param samCommandsJson The commands to be executed as a JSON String.
   * @since 0.3.0
   */
  AsyncTransactionExecutorManagerAdapter(
      ProxyReaderApi targetSamReader, LegacySamAdapter targetSam, String samCommandsJson) {
    super(targetSamReader, targetSam, null, null);

    JsonObject jsonObject = JsonUtil.getParser().fromJson(samCommandsJson, JsonObject.class);

    // extract the type and command lists
    List<String> commandsTypes =
        JsonUtil.getParser()
            .fromJson(
                jsonObject.get(SAM_COMMANDS_TYPES).getAsJsonArray(),
                new TypeToken<ArrayList<String>>() {}.getType());
    JsonArray commands = jsonObject.get(SAM_COMMANDS).getAsJsonArray();

    for (int i = 0; i < commandsTypes.size(); i++) {
      // check the resulting command class
      try {
        Class<?> classOfCommand = Class.forName(commandsTypes.get(i));
        addTargetSamCommand(
            (Command) JsonUtil.getParser().fromJson(commands.get(i), classOfCommand));
      } catch (ClassNotFoundException e) {
        throw new IllegalStateException("Invalid JSON commands object", e);
      }
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public AsyncTransactionExecutorManager processCommands() {
    processTargetSamCommandsAlreadyFinalized(false);
    return this;
  }
}
