
package Paws::SSMIncidents::GetReplicationSet;
  use Moose;
  has Arn => (is => 'ro', isa => 'Str', traits => ['ParamInQuery'], query_name => 'arn', required => 1);

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'GetReplicationSet');
  class_has _api_uri  => (isa => 'Str', is => 'ro', default => '/getReplicationSet');
  class_has _api_method  => (isa => 'Str', is => 'ro', default => 'GET');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::SSMIncidents::GetReplicationSetOutput');
1;

### main pod documentation begin ###

=head1 NAME

Paws::SSMIncidents::GetReplicationSet - Arguments for method GetReplicationSet on L<Paws::SSMIncidents>

=head1 DESCRIPTION

This class represents the parameters used for calling the method GetReplicationSet on the
L<AWS Systems Manager Incident Manager|Paws::SSMIncidents> service. Use the attributes of this class
as arguments to method GetReplicationSet.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to GetReplicationSet.

=head1 SYNOPSIS

    my $ssm-incidents = Paws->service('SSMIncidents');
    my $GetReplicationSetOutput = $ssm -incidents->GetReplicationSet(
      Arn => 'MyArn',

    );

    # Results:
    my $ReplicationSet = $GetReplicationSetOutput->ReplicationSet;

    # Returns a L<Paws::SSMIncidents::GetReplicationSetOutput> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/ssm-incidents/GetReplicationSet>

=head1 ATTRIBUTES


=head2 B<REQUIRED> Arn => Str

The Amazon Resource Name (ARN) of the replication set you want to
retrieve.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method GetReplicationSet in L<Paws::SSMIncidents>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

