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

import React, { useEffect, useState } from 'react';
import {
  EuiPanel,
  EuiTitle,
  EuiTable,
  EuiTableHeaderCell,
  EuiTableRowCell,
  EuiTableBody,
  EuiTableHeader,
  EuiTableRow,
  EuiLoadingSpinner,
  EuiText,
  EuiSpacer,
  EuiBadge,
} from '@elastic/eui';
import { CoreServicesContext } from '../../../../components/CoreServices/CoreServices';
import { Detector } from '../../../../models/interfaces';

interface TopAnomaliesChartProps {
  dataSourceId?: string;
  detectors: Detector[];
}

interface AnomalyEntity {
  entity: string;
  detectorName: string;
  anomalyScore: number;
  anomalyGrade: number;
  timestamp: string;
  index: string;
}

export function TopAnomaliesChart({ dataSourceId, detectors }: TopAnomaliesChartProps) {
  const core = React.useContext(CoreServicesContext);
  const [topAnomalies, setTopAnomalies] = useState<AnomalyEntity[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch top anomalies for HC detectors
  useEffect(() => {
    const fetchTopAnomalies = async () => {
      if (!detectors || detectors.length === 0 || !core) return;

      setLoading(true);
      setError(null);

      try {
        console.log('All detectors:', detectors);
        
        // Filter for HC (High Cardinality) detectors
        const hcDetectors = detectors.filter(detector => {
          console.log(`Detector ${detector.id}:`, {
            name: detector.name,
            categoryField: detector.categoryField,
            hasCategoryField: !!detector.categoryField,
            categoryFieldLength: detector.categoryField?.length,
            categoryFieldType: typeof detector.categoryField,
            // Check other possible locations for category field
            uiMetadata: detector.uiMetadata,
            featureAttributes: detector.featureAttributes,
            // Check if detector has any entity-related fields
            indices: detector.indices,
            description: detector.description
          });
          
          // Check if detector has category field (which makes it HC)
          // Also check if it might be HC based on other indicators
          const hasCategoryField = detector.categoryField && 
                                 Array.isArray(detector.categoryField) && 
                                 detector.categoryField.length > 0;
          
          // Alternative check: look for entity-related patterns in description or name
          const hasEntityIndicators = detector.description?.toLowerCase().includes('entity') ||
                                    detector.description?.toLowerCase().includes('category') ||
                                    detector.description?.toLowerCase().includes('group') ||
                                    detector.name?.toLowerCase().includes('entity') ||
                                    detector.name?.toLowerCase().includes('category') ||
                                    detector.name?.toLowerCase().includes('group');
          
          console.log(`Detector ${detector.id} HC check:`, {
            hasCategoryField,
            hasEntityIndicators,
            isHC: hasCategoryField || hasEntityIndicators
          });
          
          return hasCategoryField || hasEntityIndicators;
        });

        console.log('HC detectors found:', hcDetectors.length, hcDetectors);

        if (hcDetectors.length === 0) {
          setTopAnomalies([]);
          return;
        }

        const anomalies: AnomalyEntity[] = [];

        // For each HC detector, fetch anomaly results and get top entities
        for (const detector of hcDetectors.slice(0, 3)) { // Limit to 3 detectors
          try {
            console.log(`Fetching anomalies for detector: ${detector.id}`);
            
            // Use the existing getAnomalyResults endpoint
            const response = await core.http.get(
              `/api/opensearch/ad/detectors/${detector.id}/results/false`,
              {
                query: {
                  dataSourceId: dataSourceId || '',
                  size: 50, // Get more results to find top entities
                  sortField: 'anomalyGrade',
                  sortDirection: 'desc',
                  anomalyThreshold: 0.1, // Only get significant anomalies
                },
              }
            );

            console.log(`Response for detector ${detector.id}:`, response);

            if (response.body && response.body.response && response.body.response.results) {
              const detectorResults = response.body.response.results;
              console.log(`Found ${detectorResults.length} results for detector ${detector.id}`);
              
              // Group results by entity and calculate max anomaly score per entity
              const entityMap = new Map<string, { score: number; grade: number; timestamp: string }>();
              
              detectorResults.forEach((result: any) => {
                console.log('Processing result:', result);
                if (result.entity && result.entity.length > 0) {
                  result.entity.forEach((entity: any) => {
                    const entityKey = entity.value;
                    const currentMax = entityMap.get(entityKey);
                    
                    if (!currentMax || result.anomalyGrade > currentMax.grade) {
                      entityMap.set(entityKey, {
                        score: result.anomalyGrade || 0, // Use anomalyGrade as score for now
                        grade: result.anomalyGrade || 0,
                        timestamp: new Date(result.startTime).toLocaleString(),
                      });
                    }
                  });
                }
              });

              console.log(`Entity map for detector ${detector.id}:`, entityMap);

              // Convert to array and sort by anomaly grade
              const detectorAnomalies = Array.from(entityMap.entries())
                .map(([entity, data]) => ({
                  entity,
                  detectorName: detector.name || detector.id,
                  anomalyScore: data.score,
                  anomalyGrade: data.grade,
                  timestamp: data.timestamp,
                  index: detector.indices?.[0] || 'N/A',
                }))
                .sort((a, b) => b.anomalyGrade - a.anomalyGrade)
                .slice(0, 3); // Get top 3 per detector

              console.log(`Detector anomalies for ${detector.id}:`, detectorAnomalies);
              anomalies.push(...detectorAnomalies);
            } else {
              console.log(`No results found for detector ${detector.id}`);
              // If no results, create a placeholder entry to show the detector exists
              anomalies.push({
                entity: 'No anomalies detected',
                detectorName: detector.name || detector.id,
                anomalyScore: 0,
                anomalyGrade: 0,
                timestamp: 'N/A',
                index: detector.indices?.[0] || 'N/A',
              });
            }
          } catch (detectorError) {
            console.warn(`Failed to fetch anomalies for detector ${detector.id}:`, detectorError);
            // If API call fails, create a placeholder entry to show the detector exists
            anomalies.push({
              entity: 'API Error - Check console',
              detectorName: detector.name || detector.id,
              anomalyScore: 0,
              anomalyGrade: 0,
              timestamp: 'Error',
              index: detector.indices?.[0] || 'N/A',
            });
          }
        }

        console.log('All anomalies collected:', anomalies);

        // Sort by anomaly grade and take top 3 overall
        const sortedAnomalies = anomalies
          .sort((a, b) => b.anomalyGrade - a.anomalyGrade)
          .slice(0, 3);

        console.log('Final sorted anomalies:', sortedAnomalies);
        setTopAnomalies(sortedAnomalies);
      } catch (err) {
        console.error('Error fetching top anomalies:', err);
        setError('Failed to fetch anomaly data. Please try again later.');
      } finally {
        setLoading(false);
      }
    };

    fetchTopAnomalies();
  }, [detectors, dataSourceId, core]);

  const getAnomalyGradeColor = (grade: number) => {
    if (grade >= 0.8) return 'danger';
    if (grade >= 0.6) return 'warning';
    if (grade >= 0.4) return 'primary';
    return 'default';
  };

  const getAnomalyScoreColor = (score: number) => {
    if (score >= 0.8) return 'danger';
    if (score >= 0.6) return 'warning';
    if (score >= 0.4) return 'primary';
    return 'default';
  };

  if (loading) {
    return (
      <EuiPanel>
        <EuiTitle size="s">
          <h3>Top Anomalies by HC Detectors</h3>
        </EuiTitle>
        <EuiSpacer size="m" />
        <div style={{ textAlign: 'center', padding: '20px' }}>
          <EuiLoadingSpinner size="l" />
          <EuiSpacer size="s" />
          <EuiText size="s" color="subdued">
            Loading anomaly data...
          </EuiText>
        </div>
      </EuiPanel>
    );
  }

  if (error) {
    return (
      <EuiPanel>
        <EuiTitle size="s">
          <h3>Top Anomalies by HC Detectors</h3>
        </EuiTitle>
        <EuiSpacer size="m" />
        <EuiText size="s" color="danger">
          {error}
        </EuiText>
      </EuiPanel>
    );
  }

  if (!core) {
    return (
      <EuiPanel>
        <EuiTitle size="s">
          <h3>Top Anomalies by HC Detectors</h3>
        </EuiTitle>
        <EuiSpacer size="m" />
        <EuiText size="s" color="danger">
          Core services not available. Please refresh the page.
        </EuiText>
      </EuiPanel>
    );
  }

  if (topAnomalies.length === 0) {
    // Add debug information to help troubleshoot
    const hcDetectors = detectors.filter(detector => {
      const hasCategoryField = detector.categoryField && 
                             Array.isArray(detector.categoryField) && 
                             detector.categoryField.length > 0;
      
      const hasEntityIndicators = detector.description?.toLowerCase().includes('entity') ||
                                detector.description?.toLowerCase().includes('category') ||
                                detector.description?.toLowerCase().includes('group') ||
                                detector.name?.toLowerCase().includes('entity') ||
                                detector.name?.toLowerCase().includes('category') ||
                                detector.name?.toLowerCase().includes('group');
      
      return hasCategoryField || hasEntityIndicators;
    });
    
    const nonHcDetectors = detectors.filter(detector => {
      const hasCategoryField = detector.categoryField && 
                             Array.isArray(detector.categoryField) && 
                             detector.categoryField.length > 0;
      
      const hasEntityIndicators = detector.description?.toLowerCase().includes('entity') ||
                                detector.description?.toLowerCase().includes('category') ||
                                detector.description?.toLowerCase().includes('group') ||
                                detector.name?.toLowerCase().includes('entity') ||
                                detector.name?.toLowerCase().includes('category') ||
                                detector.name?.toLowerCase().includes('group');
      
      return !(hasCategoryField || hasEntityIndicators);
    });

    return (
      <EuiPanel>
        <EuiTitle size="s">
          <h3>Top Anomalies by HC Detectors</h3>
        </EuiTitle>
        <EuiSpacer size="m" />
        <EuiText size="s" color="subdued">
          No high cardinality detectors found or no anomaly data available.
        </EuiText>
        
        {/* Debug Information */}
        <EuiSpacer size="m" />
        <EuiText size="xs" color="subdued">
          <strong>Debug Info:</strong>
          <br />
          Total detectors: {detectors.length}
          <br />
          HC detectors found: {hcDetectors.length}
          <br />
          Non-HC detectors: {nonHcDetectors.length}
        </EuiText>
        
        {hcDetectors.length > 0 && (
          <>
            <EuiSpacer size="s" />
            <EuiText size="xs" color="subdued">
              <strong>HC Detectors:</strong>
              {hcDetectors.map(detector => {
                const hasCategoryField = detector.categoryField && 
                                       Array.isArray(detector.categoryField) && 
                                       detector.categoryField.length > 0;
                
                const hasEntityIndicators = detector.description?.toLowerCase().includes('entity') ||
                                          detector.description?.toLowerCase().includes('category') ||
                                          detector.description?.toLowerCase().includes('group') ||
                                          detector.name?.toLowerCase().includes('entity') ||
                                          detector.name?.toLowerCase().includes('category') ||
                                          detector.name?.toLowerCase().includes('group');
                
                return (
                  <div key={detector.id}>
                    • {detector.name || detector.id} (ID: {detector.id})
                    <br />
                    &nbsp;&nbsp;Category Field: {JSON.stringify(detector.categoryField)}
                    <br />
                    &nbsp;&nbsp;Has Category Field: {hasCategoryField ? 'Yes' : 'No'}
                    <br />
                    &nbsp;&nbsp;Has Entity Indicators: {hasEntityIndicators ? 'Yes' : 'No'}
                    <br />
                    &nbsp;&nbsp;Description: {detector.description || 'N/A'}
                  </div>
                );
              })}
            </EuiText>
          </>
        )}
        
        {nonHcDetectors.length > 0 && (
          <>
            <EuiSpacer size="s" />
            <EuiText size="xs" color="subdued">
              <strong>Non-HC Detectors:</strong>
              {nonHcDetectors.map(detector => {
                const hasCategoryField = detector.categoryField && 
                                       Array.isArray(detector.categoryField) && 
                                       detector.categoryField.length > 0;
                
                const hasEntityIndicators = detector.description?.toLowerCase().includes('entity') ||
                                          detector.description?.toLowerCase().includes('category') ||
                                          detector.description?.toLowerCase().includes('group') ||
                                          detector.name?.toLowerCase().includes('entity') ||
                                          detector.name?.toLowerCase().includes('category') ||
                                          detector.name?.toLowerCase().includes('group');
                
                return (
                  <div key={detector.id}>
                    • {detector.name || detector.id} (ID: {detector.id})
                    <br />
                    &nbsp;&nbsp;Category Field: {JSON.stringify(detector.categoryField)}
                    <br />
                    &nbsp;&nbsp;Has Category Field: {hasCategoryField ? 'Yes' : 'No'}
                    <br />
                    &nbsp;&nbsp;Has Entity Indicators: {hasEntityIndicators ? 'Yes' : 'No'}
                    <br />
                    &nbsp;&nbsp;Description: {detector.description || 'N/A'}
                  </div>
                );
              })}
            </EuiText>
          </>
        )}
      </EuiPanel>
    );
  }

  return (
    <EuiPanel>
      <EuiTitle size="s">
        <h3>Top Anomalies by HC Detectors</h3>
      </EuiTitle>
      <EuiSpacer size="m" />
      <EuiText size="s" color="subdued">
        Top 3 entities with highest anomaly grades from High Cardinality detectors
      </EuiText>
      <EuiSpacer size="m" />
      
      <EuiTable>
        <EuiTableHeader>
          <EuiTableHeaderCell>Entity</EuiTableHeaderCell>
          <EuiTableHeaderCell>Detector</EuiTableHeaderCell>
          <EuiTableHeaderCell>Anomaly Score</EuiTableHeaderCell>
          <EuiTableHeaderCell>Anomaly Grade</EuiTableHeaderCell>
          <EuiTableHeaderCell>Index</EuiTableHeaderCell>
          <EuiTableHeaderCell>Timestamp</EuiTableHeaderCell>
        </EuiTableHeader>
        <EuiTableBody>
          {topAnomalies.map((anomaly, index) => (
            <EuiTableRow key={index}>
              <EuiTableRowCell>
                <EuiText size="s">
                  <strong>{anomaly.entity}</strong>
                </EuiText>
              </EuiTableRowCell>
              <EuiTableRowCell>
                <EuiText size="s">
                  {anomaly.detectorName}
                </EuiText>
              </EuiTableRowCell>
              <EuiTableRowCell>
                <EuiBadge color={getAnomalyScoreColor(anomaly.anomalyScore)}>
                  {anomaly.anomalyScore.toFixed(3)}
                </EuiBadge>
              </EuiTableRowCell>
              <EuiTableRowCell>
                <EuiBadge color={getAnomalyGradeColor(anomaly.anomalyGrade)}>
                  {anomaly.anomalyGrade.toFixed(3)}
                </EuiBadge>
              </EuiTableRowCell>
              <EuiTableRowCell>
                <EuiText size="s">
                  {anomaly.index}
                </EuiText>
              </EuiTableRowCell>
              <EuiTableRowCell>
                <EuiText size="s">
                  {anomaly.timestamp}
                </EuiText>
              </EuiTableRowCell>
            </EuiTableRow>
          ))}
        </EuiTableBody>
      </EuiTable>
    </EuiPanel>
  );
} 