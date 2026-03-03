/* **************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/
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

import static org.eclipse.keyple.card.calypso.crypto.legacysam.DtoAdapters.*;
import static org.eclipse.keyple.card.calypso.crypto.legacysam.LegacySamConstants.MAX_KEY_RECORD_NUMBER;
import static org.eclipse.keyple.card.calypso.crypto.legacysam.LegacySamConstants.MIN_KEY_RECORD_NUMBER;

import java.util.*;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keyple.core.util.json.JsonUtil;
import org.eclipse.keypop.calypso.crypto.legacysam.GetDataTag;
import org.eclipse.keypop.calypso.crypto.legacysam.SystemKeyType;
import org.eclipse.keypop.calypso.crypto.legacysam.transaction.*;
import org.eclipse.keypop.card.ProxyReaderApi;

/**
 * Adapter of {@link FreeTransactionManagerAdapter}.
 *
 * @since 0.1.0
 */
final class FreeTransactionManagerAdapter extends CommonTransactionManagerAdapter
    implements FreeTransactionManager {
  private static final String MSG_INPUT_OUTPUT_DATA = "input/output data";
  private static final String MSG_SIGNATURE_SIZE = "signature size";
  private static final String MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8 =
      "key diversifier size is in range [1..8]";

  /* Final fields */
  private final byte[] samKeyDiversifier;

  /* Dynamic fields */
  private byte[] currentKeyDiversifier;

  /**
   * Constructs a new instance with the specified target SAM context and security settings.
   *
   * @param targetSamReader The reader through which the target SAM communicates.
   * @param targetSam The target legacy SAM.
   * @since 0.3.0
   */
  FreeTransactionManagerAdapter(ProxyReaderApi targetSamReader, LegacySamAdapter targetSam) {
    super(targetSamReader, targetSam, null, null);
    samKeyDiversifier = targetSam.getSerialNumber();
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.6.0
   */
  @Override
  public FreeTransactionManager prepareGetData(GetDataTag tag) {
    Assert.getInstance().notNull(tag, "tag");
    addTargetSamCommand(new CommandGetData(getContext(), tag));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.6.0
   */
  @Override
  public FreeTransactionManager prepareGenerateCardAsymmetricKeyPair(
      KeyPairContainer keyPairContainer) {
    Assert.getInstance().notNull(keyPairContainer, "keyPairContainer");
    if (!(keyPairContainer instanceof KeyPairContainerAdapter)) {
      throw new IllegalArgumentException(
          "The provided keyPairContainer must be an instance of 'KeyPairContainerAdapter'");
    }
    addTargetSamCommand(new CommandCardGenerateAsymmetricKeyPair(getContext(), keyPairContainer));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.6.0
   */
  @Override
  public FreeTransactionManager prepareComputeCardCertificate(
      LegacyCardCertificateComputationData data) {
    Assert.getInstance().notNull(data, "data");
    if (!(data instanceof LegacyCardCertificateComputationDataAdapter)) {
      throw new IllegalArgumentException(
          "The provided data must be an instance of 'LegacyCardCertificateComputationDataAdapter'");
    }
    addTargetSamCommand(new CommandPsoComputeCertificate(getContext(), data));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public FreeTransactionManager preparePlainWriteLock(
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
   * @since 0.1.0
   */
  @Override
  public FreeTransactionManagerAdapter prepareComputeSignature(SignatureComputationData<?> data) {

    if (data instanceof BasicSignatureComputationDataAdapter) {
      // Basic signature
      BasicSignatureComputationDataAdapter dataAdapter =
          (BasicSignatureComputationDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
          .notNull(dataAdapter.getData(), "data to sign")
          .isInRange(dataAdapter.getData().length, 1, 208, "length of data to sign")
          .isTrue(
              dataAdapter.getData().length % 8 == 0, "length of data to sign is a multiple of 8")
          .isInRange(dataAdapter.getSignatureSize(), 1, 8, MSG_SIGNATURE_SIZE)
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      addTargetSamCommand(new CommandDataCipher(getContext(), dataAdapter, null));

    } else if (data instanceof TraceableSignatureComputationDataAdapter) {
      // Traceable signature
      TraceableSignatureComputationDataAdapter dataAdapter =
          (TraceableSignatureComputationDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
          .notNull(dataAdapter.getData(), "data to sign")
          .isInRange(
              dataAdapter.getData().length,
              1,
              dataAdapter.isSamTraceabilityMode() ? 206 : 208,
              "length of data to sign")
          .isInRange(dataAdapter.getSignatureSize(), 1, 8, MSG_SIGNATURE_SIZE)
          .isTrue(
              !dataAdapter.isSamTraceabilityMode()
                  || (dataAdapter.getTraceabilityOffset() >= 0
                      && dataAdapter.getTraceabilityOffset()
                          <= ((dataAdapter.getData().length * 8)
                              - (dataAdapter.getSamTraceabilityMode()
                                      == SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER
                                  ? 7 * 8
                                  : 8 * 8))),
              "traceability offset is in range [0.."
                  + ((dataAdapter.getData().length * 8)
                      - (dataAdapter.getSamTraceabilityMode()
                              == SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER
                          ? 7 * 8
                          : 8 * 8))
                  + "]")
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      addTargetSamCommand(new CommandPsoComputeSignature(getContext(), dataAdapter));

    } else {
      throw new IllegalArgumentException(
          "The provided data must be an instance of 'BasicSignatureComputationDataAdapter'"
              + " or 'TraceableSignatureComputationDataAdapter'");
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public FreeTransactionManagerAdapter prepareVerifySignature(SignatureVerificationData<?> data) {
    if (data instanceof BasicSignatureVerificationDataAdapter) {
      // Basic signature
      BasicSignatureVerificationDataAdapter dataAdapter =
          (BasicSignatureVerificationDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
          .notNull(dataAdapter.getData(), "signed data to verify")
          .isInRange(dataAdapter.getData().length, 1, 208, "length of signed data to verify")
          .isTrue(
              dataAdapter.getData().length % 8 == 0, "length of data to verify is a multiple of 8")
          .notNull(dataAdapter.getSignature(), "signature")
          .isInRange(dataAdapter.getSignature().length, 1, 8, MSG_SIGNATURE_SIZE)
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      addTargetSamCommand(new CommandDataCipher(getContext(), null, dataAdapter));

    } else if (data instanceof TraceableSignatureVerificationDataAdapter) {
      // Traceable signature
      TraceableSignatureVerificationDataAdapter dataAdapter =
          (TraceableSignatureVerificationDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
          .notNull(dataAdapter.getData(), "signed data to verify")
          .isInRange(
              dataAdapter.getData().length,
              1,
              dataAdapter.isSamTraceabilityMode() ? 206 : 208,
              "length of signed data to verify")
          .notNull(dataAdapter.getSignature(), "signature")
          .isInRange(dataAdapter.getSignature().length, 1, 8, MSG_SIGNATURE_SIZE)
          .isTrue(
              !dataAdapter.isSamTraceabilityMode()
                  || (dataAdapter.getTraceabilityOffset() >= 0
                      && dataAdapter.getTraceabilityOffset()
                          <= ((dataAdapter.getData().length * 8)
                              - (dataAdapter.getSamTraceabilityMode()
                                      == SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER
                                  ? 7 * 8
                                  : 8 * 8))),
              "traceability offset is in range [0.."
                  + ((dataAdapter.getData().length * 8)
                      - (dataAdapter.getSamTraceabilityMode()
                              == SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER
                          ? 7 * 8
                          : 8 * 8))
                  + "]")
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      // Check SAM revocation status if requested.
      if (dataAdapter.getSamRevocationService() != null) {
        // Extract the SAM serial number and the counter value from the data.
        byte[] samSerialNumber =
            ByteArrayUtil.extractBytes(
                dataAdapter.getData(),
                dataAdapter.getTraceabilityOffset(),
                dataAdapter.getSamTraceabilityMode() == SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER
                    ? 3
                    : 4);

        int samCounterValue =
            ByteArrayUtil.extractInt(
                ByteArrayUtil.extractBytes(
                    dataAdapter.getData(),
                    dataAdapter.getTraceabilityOffset()
                        + (dataAdapter.getSamTraceabilityMode()
                                == SamTraceabilityMode.TRUNCATED_SERIAL_NUMBER
                            ? 3 * 8
                            : 4 * 8),
                    3),
                0,
                3,
                false);

        // Is SAM revoked ?
        if (dataAdapter.getSamRevocationService().isSamRevoked(samSerialNumber, samCounterValue)) {
          throw new SamRevokedException(
              String.format(
                  "SAM with serial number [%s] and counter value [%d] is revoked",
                  HexUtil.toHex(samSerialNumber), samCounterValue));
        }
      }

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      addTargetSamCommand(new CommandPsoVerifySignature(getContext(), dataAdapter));

    } else {
      throw new IllegalArgumentException(
          "The provided data must be an instance of 'SignatureVerificationDataAdapter'");
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public FreeTransactionManager prepareReadSamParameters() {
    addTargetSamCommand(new CommandReadParameters(getContext()));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public FreeTransactionManagerAdapter prepareReadSystemKeyParameters(SystemKeyType systemKeyType) {
    Assert.getInstance().notNull(systemKeyType, "systemKeyType");
    addTargetSamCommand(new CommandReadKeyParameters(getContext(), systemKeyType));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public FreeTransactionManager prepareReadWorkKeyParameters(int recordNumber) {
    Assert.getInstance()
        .isInRange(recordNumber, MIN_KEY_RECORD_NUMBER, MAX_KEY_RECORD_NUMBER, "recordNumber");
    addTargetSamCommand(new CommandReadKeyParameters(getContext(), recordNumber));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.9.0
   */
  @Override
  public FreeTransactionManager prepareReadWorkKeyParameters(byte kif, byte kvc) {
    addTargetSamCommand(new CommandReadKeyParameters(getContext(), kif, kvc));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public FreeTransactionManagerAdapter prepareReadCounterStatus(int counterNumber) {
    Assert.getInstance()
        .isInRange(
            counterNumber,
            LegacySamConstants.MIN_COUNTER_NUMBER,
            LegacySamConstants.MAX_COUNTER_NUMBER,
            "counterNumber");
    for (Command command : getTargetSamCommands()) {
      if (command instanceof CommandReadCounter
          && ((CommandReadCounter) command).getCounterFileRecordNumber()
              == LegacySamConstants.COUNTER_TO_RECORD_LOOKUP[counterNumber]) {
        // already scheduled
        return this;
      }
    }
    addTargetSamCommand(
        new CommandReadCounter(
            getContext(), LegacySamConstants.COUNTER_TO_RECORD_LOOKUP[counterNumber]));
    addTargetSamCommand(
        new CommandReadCeilings(
            getContext(), LegacySamConstants.COUNTER_TO_RECORD_LOOKUP[counterNumber]));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public FreeTransactionManagerAdapter prepareReadAllCountersStatus() {
    for (int i = 0; i < 3; i++) {
      addTargetSamCommand(new CommandReadCounter(getContext(), i));
      addTargetSamCommand(new CommandReadCeilings(getContext(), i));
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.3.0
   */
  @Override
  public String exportTargetSamContextForAsyncTransaction() {

    List<Command> commands = new ArrayList<>();

    // read system key parameters if not available
    if (getContext().getTargetSam().getSystemKeyParameter(SystemKeyType.PERSONALIZATION) == null) {
      commands.add(new CommandReadKeyParameters(getContext(), SystemKeyType.PERSONALIZATION));
    }
    if (getContext().getTargetSam().getSystemKeyParameter(SystemKeyType.KEY_MANAGEMENT) == null) {
      commands.add(new CommandReadKeyParameters(getContext(), SystemKeyType.KEY_MANAGEMENT));
    }
    if (getContext().getTargetSam().getSystemKeyParameter(SystemKeyType.RELOADING) == null) {
      commands.add(new CommandReadKeyParameters(getContext(), SystemKeyType.RELOADING));
    }
    processTargetSamCommands(commands);
    commands.clear();

    // The parameter PAR4 of each key contains the associated counter number (if a key has no
    // associated counter, the value of its PAR4 is set to 0)
    int counterPersonalization =
        getContext()
                .getTargetSam()
                .getSystemKeyParameter(SystemKeyType.PERSONALIZATION)
                .getParameterValue(4)
            & 0xFF;
    int counterKeyManagement =
        getContext()
                .getTargetSam()
                .getSystemKeyParameter(SystemKeyType.KEY_MANAGEMENT)
                .getParameterValue(4)
            & 0xFF;
    int counterReloading =
        getContext()
                .getTargetSam()
                .getSystemKeyParameter(SystemKeyType.RELOADING)
                .getParameterValue(4)
            & 0xFF;

    // store serial number, KVCs and counter number if any in the target SAM context
    TargetSamContextDto targetSamContextDto =
        new TargetSamContextDto(getContext().getTargetSam().getSerialNumber(), false);
    targetSamContextDto
        .getSystemKeyTypeToKvcMap()
        .put(
            SystemKeyType.PERSONALIZATION,
            getContext()
                .getTargetSam()
                .getSystemKeyParameter(SystemKeyType.PERSONALIZATION)
                .getKvc());
    targetSamContextDto
        .getSystemKeyTypeToKvcMap()
        .put(
            SystemKeyType.KEY_MANAGEMENT,
            getContext()
                .getTargetSam()
                .getSystemKeyParameter(SystemKeyType.KEY_MANAGEMENT)
                .getKvc());
    targetSamContextDto
        .getSystemKeyTypeToKvcMap()
        .put(
            SystemKeyType.RELOADING,
            getContext().getTargetSam().getSystemKeyParameter(SystemKeyType.RELOADING).getKvc());
    if (counterPersonalization != 0) {
      targetSamContextDto
          .getSystemKeyTypeToCounterNumberMap()
          .put(SystemKeyType.PERSONALIZATION, counterPersonalization);
    }
    if (counterKeyManagement != 0) {
      targetSamContextDto
          .getSystemKeyTypeToCounterNumberMap()
          .put(SystemKeyType.KEY_MANAGEMENT, counterKeyManagement);
    }
    if (counterReloading != 0) {
      targetSamContextDto
          .getSystemKeyTypeToCounterNumberMap()
          .put(SystemKeyType.RELOADING, counterReloading);
    }

    // compute needed counter file records
    Set<Integer> counterFileRecordNumbers = new HashSet<>(3);
    if (counterPersonalization != 0) {
      counterFileRecordNumbers.add(
          LegacySamConstants.COUNTER_TO_RECORD_LOOKUP[counterPersonalization]);
    }
    if (counterKeyManagement != 0) {
      counterFileRecordNumbers.add(
          LegacySamConstants.COUNTER_TO_RECORD_LOOKUP[counterKeyManagement]);
    }
    if (counterReloading != 0) {
      counterFileRecordNumbers.add(LegacySamConstants.COUNTER_TO_RECORD_LOOKUP[counterReloading]);
    }

    // read counters
    for (Integer counterFileRecordNumber : counterFileRecordNumbers) {
      commands.add(new CommandReadCounter(getContext(), counterFileRecordNumber));
    }
    processTargetSamCommands(commands);

    if (counterPersonalization != 0) {
      targetSamContextDto
          .getCounterNumberToCounterValueMap()
          .put(
              counterPersonalization,
              getContext().getTargetSam().getCounter(counterPersonalization));
    }
    if (counterKeyManagement != 0) {
      targetSamContextDto
          .getCounterNumberToCounterValueMap()
          .put(counterKeyManagement, getContext().getTargetSam().getCounter(counterKeyManagement));
    }
    if (counterReloading != 0) {
      targetSamContextDto
          .getCounterNumberToCounterValueMap()
          .put(counterReloading, getContext().getTargetSam().getCounter(counterReloading));
    }

    // export as json
    return JsonUtil.toJson(targetSamContextDto);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public FreeTransactionManagerAdapter processCommands() {
    processTargetSamCommands(false);
    return this;
  }

  /**
   * Prepares a "SelectDiversifier" command using a specific or the default key diversifier if it is
   * not already selected.
   *
   * @param specificKeyDiversifier The specific key diversifier (optional).
   * @since 0.1.0
   */
  private void prepareSelectDiversifierIfNeeded(byte[] specificKeyDiversifier) {
    if (specificKeyDiversifier != null) {
      if (!Arrays.equals(specificKeyDiversifier, currentKeyDiversifier)) {
        currentKeyDiversifier = specificKeyDiversifier;
        prepareSelectDiversifier();
      }
    } else {
      prepareSelectDiversifierIfNeeded();
    }
  }

  /**
   * Prepares a "SelectDiversifier" command using the default key diversifier if it is not already
   * selected.
   *
   * @since 0.1.0
   */
  private void prepareSelectDiversifierIfNeeded() {
    if (!Arrays.equals(currentKeyDiversifier, samKeyDiversifier)) {
      currentKeyDiversifier = samKeyDiversifier;
      prepareSelectDiversifier();
    }
  }

  /** Prepares a "SelectDiversifier" command using the current key diversifier. */
  private void prepareSelectDiversifier() {
    addTargetSamCommand(new CommandSelectDiversifier(getContext(), currentKeyDiversifier));
  }
}
