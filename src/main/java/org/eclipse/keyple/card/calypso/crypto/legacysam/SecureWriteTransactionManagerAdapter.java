/* **************************************************************************************
 * Copyright (c) 2024 Calypso Networks Association https://calypsonet.org/
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

import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keypop.calypso.crypto.legacysam.CounterIncrementAccess;
import org.eclipse.keypop.calypso.crypto.legacysam.SystemKeyType;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.SecureWriteTransactionManager;
import org.eclipse.keypop.card.ProxyReaderApi;

/**
 * Adapter of {@link SecureWriteTransactionManager}.
 *
 * @since 0.9.0
 */
final class SecureWriteTransactionManagerAdapter extends CommonTransactionManagerAdapter
    implements SecureWriteTransactionManager {

  /**
   * Constructor
   *
   * @param targetSamReader The reader through which the target SAM communicates.
   * @param targetSam The target legacy SAM.
   * @param controlSamReader The reader through which the control SAM communicates.
   * @param controlSam The control legacy SAM.
   */
  SecureWriteTransactionManagerAdapter(
      ProxyReaderApi targetSamReader,
      LegacySamAdapter targetSam,
      ProxyReaderApi controlSamReader,
      LegacySamAdapter controlSam) {
    super(targetSamReader, targetSam, controlSamReader, controlSam);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareWriteSamParameters(byte[] parameters) {
    Assert.getInstance()
        .notNull(parameters, "parameters")
        .isEqual(parameters.length, LegacySamConstants.SAM_PARAMETERS_LENGTH, "parameters.length");
    if (getContext().getTargetSam().getSystemKeyParameter(SystemKeyType.PERSONALIZATION) == null) {
      addTargetSamCommand(
          new CommandReadKeyParameters(getContext(), SystemKeyType.PERSONALIZATION));
    }
    addTargetSamCommand(new CommandGetChallenge(getContext(), 8));
    addTargetSamCommand(new CommandWriteSamParameters(getContext(), parameters));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareTransferSystemKey(
      SystemKeyType systemKeyType, byte kvc, byte[] systemKeyParameters) {
    return prepareTransferSystemKeyInternal(systemKeyType, kvc, systemKeyParameters, false);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareTransferSystemKeyDiversified(
      SystemKeyType systemKeyType, byte kvc, byte[] systemKeyParameters) {
    return prepareTransferSystemKeyInternal(systemKeyType, kvc, systemKeyParameters, true);
  }

  private SecureWriteTransactionManager prepareTransferSystemKeyInternal(
      SystemKeyType systemKeyType, byte kvc, byte[] systemKeyParameters, boolean isDiversified) {

    Assert.getInstance()
        .notNull(systemKeyType, "systemKeyType")
        .notNull(systemKeyParameters, "systemKeyParameters")
        .isEqual(
            systemKeyParameters.length,
            LegacySamConstants.KEY_PARAMETERS_LENGTH,
            "systemKeyParameters.length");

    if (getContext().getTargetSam().getSystemKeyParameter(SystemKeyType.PERSONALIZATION) == null) {
      addTargetSamCommand(
          new CommandReadKeyParameters(getContext(), SystemKeyType.PERSONALIZATION));
    }

    addTargetSamCommand(new CommandGetChallenge(getContext(), 8));

    addTargetSamCommand(
        new CommandWriteKey(getContext(), systemKeyType, kvc, systemKeyParameters, isDiversified));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareTransferWorkKey(
      byte kif, byte kvc, byte[] workKeyParameters, int targetRecordNumber) {
    return prepareTransferWorkKeyInternal(
        kif, kvc, workKeyParameters, targetRecordNumber, false, null);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareTransferWorkKeyDiversified(
      byte kif, byte kvc, byte[] workKeyParameters, int targetRecordNumber) {
    return prepareTransferWorkKeyInternal(
        kif, kvc, workKeyParameters, targetRecordNumber, true, null);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareTransferWorkKeyDiversified(
      byte kif, byte kvc, byte[] workKeyParameters, int targetRecordNumber, byte[] diversifier) {
    return prepareTransferWorkKeyInternal(
        kif, kvc, workKeyParameters, targetRecordNumber, true, diversifier);
  }

  private SecureWriteTransactionManager prepareTransferWorkKeyInternal(
      byte kif,
      byte kvc,
      byte[] workKeyParameters,
      int targetRecordNumber,
      boolean diversified,
      byte[] diversifier) {

    Assert.getInstance()
        .notNull(workKeyParameters, "workKeyParameters")
        .isEqual(
            workKeyParameters.length,
            LegacySamConstants.KEY_PARAMETERS_LENGTH,
            "workKeyParameters.length")
        .isInRange(targetRecordNumber, 0, 126, "targetRecordNumber");

    if (getContext().getTargetSam().getSystemKeyParameter(SystemKeyType.KEY_MANAGEMENT) == null) {
      addTargetSamCommand(new CommandReadKeyParameters(getContext(), SystemKeyType.KEY_MANAGEMENT));
    }

    addTargetSamCommand(new CommandGetChallenge(getContext(), 8));

    if (diversifier == null) {
      addTargetSamCommand(
          new CommandWriteKey(
              getContext(), kif, kvc, targetRecordNumber, workKeyParameters, diversified));
    } else {
      addTargetSamCommand(
          new CommandWriteKey(
              getContext(), kif, kvc, targetRecordNumber, workKeyParameters, diversifier));
    }

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareTransferLock(byte lockIndex, byte lockParameters) {
    return prepareTransferLockInternal(lockIndex, lockParameters, false);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareTransferLockDiversified(
      byte lockIndex, byte lockParameters) {
    return prepareTransferLockInternal(lockIndex, lockParameters, true);
  }

  private SecureWriteTransactionManager prepareTransferLockInternal(
      byte lockIndex, byte lockParameters, boolean isDiversified) {
    if (getContext().getTargetSam().getSystemKeyParameter(SystemKeyType.KEY_MANAGEMENT) == null) {
      addTargetSamCommand(new CommandReadKeyParameters(getContext(), SystemKeyType.KEY_MANAGEMENT));
    }
    addTargetSamCommand(new CommandGetChallenge(getContext(), 8));
    addTargetSamCommand(
        new CommandWriteKey(getContext(), lockIndex, lockParameters, isDiversified));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager preparePlainWriteLock(
      byte lockIndex, byte lockParameters, byte[] lockValue) {
    Assert.getInstance()
        .notNull(lockValue, "lockValue")
        .isEqual(lockValue.length, LegacySamConstants.LOCK_VALUE_LENGTH, "lockValue.length");

    addTargetSamCommand(
        new CommandWriteKey(
            getContext(),
            CommandWriteKey.buildPlainLockDataBlock(lockIndex, lockParameters, lockValue)));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareWriteCounterCeiling(
      int counterNumber, int ceilingValue) {

    Assert.getInstance()
        .isInRange(
            counterNumber,
            LegacySamConstants.MIN_COUNTER_CEILING_NUMBER,
            LegacySamConstants.MAX_COUNTER_CEILING_NUMBER,
            "counterNumber")
        .isInRange(
            ceilingValue,
            LegacySamConstants.MIN_COUNTER_CEILING_VALUE,
            LegacySamConstants.MAX_COUNTER_CEILING_VALUE,
            "ceilingValue");

    if (getContext().getTargetSam().getSystemKeyParameter(SystemKeyType.RELOADING) == null) {
      addTargetSamCommand(new CommandReadKeyParameters(getContext(), SystemKeyType.RELOADING));
    }
    addTargetSamCommand(new CommandGetChallenge(getContext(), 8));
    addTargetSamCommand(new CommandWriteCeilings(getContext(), counterNumber, ceilingValue));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager prepareWriteCounterConfiguration(
      int counterNumber, int ceilingValue, CounterIncrementAccess counterIncrementAccess) {

    Assert.getInstance()
        .isInRange(
            counterNumber,
            LegacySamConstants.MIN_COUNTER_CEILING_NUMBER,
            LegacySamConstants.MAX_COUNTER_CEILING_NUMBER,
            "counterNumber")
        .isInRange(
            ceilingValue,
            LegacySamConstants.MIN_COUNTER_CEILING_VALUE,
            LegacySamConstants.MAX_COUNTER_CEILING_VALUE,
            "ceilingValue");

    for (Command command : getTargetSamCommands()) {
      if (command instanceof CommandWriteCeilings
          && ((CommandWriteCeilings) command).getCounterFileRecordNumber()
              == LegacySamConstants.COUNTER_TO_RECORD_LOOKUP[counterNumber]) {
        ((CommandWriteCeilings) command)
            .addCounter(counterNumber, ceilingValue, counterIncrementAccess);
        return this;
      }
    }

    if (getContext().getTargetSam().getSystemKeyParameter(SystemKeyType.RELOADING) == null) {
      addTargetSamCommand(new CommandReadKeyParameters(getContext(), SystemKeyType.RELOADING));
    }
    addTargetSamCommand(new CommandGetChallenge(getContext(), 8));
    addTargetSamCommand(
        new CommandWriteCeilings(
            getContext(), counterNumber, ceilingValue, counterIncrementAccess));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public SecureWriteTransactionManager processCommands() {
    processTargetSamCommands(false);
    return this;
  }
}
