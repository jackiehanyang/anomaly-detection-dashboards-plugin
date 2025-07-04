/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

import React from 'react';
import { render, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ConfirmDeleteDetectorsModal } from '../ConfirmDeleteDetectorsModal';
import { DetectorListItem, Monitor } from '../../../../../models/interfaces';
import { DETECTOR_STATE } from '../../../../../../server/utils/constants';

const testDetectors = [
  {
    id: 'detector-id-0',
    name: 'detector-0',
  },
  {
    id: 'detector-id-1',
    name: 'detector-1',
  },
] as DetectorListItem[];

let testMonitor = {} as { [key: string]: Monitor };
//@ts-ignore
testMonitor['detector-id-0'] = {
  id: 'monitor-id-0',
  name: 'monitor-0',
};

const defaultDeleteProps = {
  detectors: testDetectors,
  monitors: {},
  onHide: jest.fn(),
  onConfirm: jest.fn(),
  onStopDetectors: jest.fn(),
  onDeleteDetectors: jest.fn(),
  isListLoading: false,
};

describe('<ConfirmDeleteDetectorsModal /> spec', () => {
  const user = userEvent.setup();
  beforeEach(() => {
    jest.clearAllMocks();
  });
  describe('ConfirmDeleteDetectorsModal', () => {
    test('renders modal with detectors and no monitors', async () => {
      const { getByText, getAllByText } = render(
        <ConfirmDeleteDetectorsModal {...defaultDeleteProps} />
      );
      getByText('Are you sure you want to delete the selected detectors?');
      getByText('Delete detectors');
    });
    test('renders modal with detectors and 1 monitor', async () => {
      console.error = jest.fn();
      const { getByText } = render(
        <ConfirmDeleteDetectorsModal
          {...defaultDeleteProps}
          monitors={testMonitor}
        />
      );
      getByText('Are you sure you want to delete the selected detectors?');
      getByText(
        'The monitors associated with these detectors will not receive any anomaly results.'
      );
      getByText('Delete detectors');
    });
    test('should have delete button disabled if delete not typed', async () => {
      const { getByTestId, getByPlaceholderText } = render(
        <ConfirmDeleteDetectorsModal {...defaultDeleteProps} />
      );
      await waitFor(() => {});
      await user.type(getByPlaceholderText('delete'), 'foo');
      await waitFor(() => {});
      await user.click(getByTestId('confirmButton'));
      await waitFor(() => {});
      expect(defaultDeleteProps.onStopDetectors).not.toHaveBeenCalled();
      expect(defaultDeleteProps.onDeleteDetectors).not.toHaveBeenCalled();
      expect(defaultDeleteProps.onConfirm).not.toHaveBeenCalled();
    }, 5000);
    test('should have delete button enabled if delete typed', async () => {
      const { getByTestId, getByPlaceholderText } = render(
        <ConfirmDeleteDetectorsModal {...defaultDeleteProps} />
      );
      await waitFor(() => {});
      await user.type(getByPlaceholderText('delete'), 'delete');
      await waitFor(() => {});
      await user.click(getByTestId('confirmButton'));
      await waitFor(() => {});
      expect(defaultDeleteProps.onConfirm).toHaveBeenCalled();
    }, 5000);
    test('should not show callout if no detectors are running', async () => {
      const { queryByText } = render(
        <ConfirmDeleteDetectorsModal {...defaultDeleteProps} />
      );
      expect(
        queryByText('Some of the selected detectors are currently running.')
      ).toBeNull();
    });
    test('should show callout if detectors are running', async () => {
      const { queryByText } = render(
        <ConfirmDeleteDetectorsModal
          {...defaultDeleteProps}
          detectors={
            [
              {
                id: 'detector-id-0',
                name: 'detector-0',
                curState: DETECTOR_STATE.INIT,
              },
              {
                id: 'detector-id-1',
                name: 'detector-1',
                curState: DETECTOR_STATE.RUNNING,
              },
              {
                id: 'detector-id-2',
                name: 'detector-2',
              },
            ] as DetectorListItem[]
          }
        />
      );
      await waitFor(() => {});
      expect(
        queryByText('Some of the selected detectors are currently running.')
      ).not.toBeNull();
    });
    test('should call onHide() when closing', async () => {
      const { getByTestId } = render(
        <ConfirmDeleteDetectorsModal {...defaultDeleteProps} />
      );
      await waitFor(() => getByTestId('cancelButton'));
      await user.click(getByTestId('cancelButton'));
      await waitFor(() => {});
      expect(defaultDeleteProps.onHide).toHaveBeenCalled();
    });
    test('should call onStopDetectors when deleting running detectors', async () => {
      const { getByTestId, getByPlaceholderText } = render(
        <ConfirmDeleteDetectorsModal
          {...defaultDeleteProps}
          detectors={
            [
              {
                id: 'detector-id-0',
                name: 'detector-0',
                curState: DETECTOR_STATE.INIT,
              },
            ] as DetectorListItem[]
          }
        />
      );
      // Try clicking before 'delete' has been typed
      await waitFor(() => getByTestId('confirmButton'));
      await user.click(getByTestId('confirmButton'));
      await waitFor(() => {});
      expect(defaultDeleteProps.onStopDetectors).not.toHaveBeenCalled();
      await user.type(getByPlaceholderText('delete'), 'delete');
      await waitFor(() => {});
      await user.click(getByTestId('confirmButton'));
      await waitFor(() => {});
      expect(defaultDeleteProps.onStopDetectors).toHaveBeenCalled();
    });
  });
});
